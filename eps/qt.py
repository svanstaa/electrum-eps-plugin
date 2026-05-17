# eps/qt.py
#
# Electrum plugin entry point for the Qt GUI.
# Manages the server lifecycle, settings UI, and wallet hooks.

import threading
import logging
from typing import Optional, TYPE_CHECKING

# Electrum 4.5+ uses PyQt6; older versions use PyQt5.
try:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
        QPushButton, QCheckBox, QSpinBox, QGroupBox,
        QProgressDialog, QMessageBox, QFileDialog,
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
    from PyQt6.QtGui import QFont
    _ECHO_PASSWORD = QLineEdit.EchoMode.Password
    _WINDOW_MODAL  = Qt.WindowModality.WindowModal
except ImportError:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
        QPushButton, QCheckBox, QSpinBox, QGroupBox,
        QProgressDialog, QMessageBox, QFileDialog,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
    from PyQt5.QtGui import QFont
    _ECHO_PASSWORD = QLineEdit.Password
    _WINDOW_MODAL  = Qt.WindowModal

from electrum.plugin import BasePlugin, hook
from electrum.i18n import _

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qt.main_window import ElectrumWindow

logger = logging.getLogger("eps.plugin")


# ---------------------------------------------------------------------------
# Thread-safe bridge for delivering status messages from background threads
# (server-accept loop, per-client handlers, notifier) into the GUI thread.
#
# Qt widgets must only be touched from the thread that owns the QApplication
# event loop. `pyqtSignal.emit()` is itself thread-safe, and the connected
# slot is automatically queued onto the receiver's thread (the GUI thread).
# ---------------------------------------------------------------------------

class _StatusBridge(QObject):
    status_changed = pyqtSignal(str, bool)  # (message, is_error)


# ---------------------------------------------------------------------------
# Worker thread for import + rescan (keeps GUI responsive)
# ---------------------------------------------------------------------------

class ImportWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # (success, message)

    def __init__(self, rpc, wallet, gap_limit):
        super().__init__()
        self.rpc = rpc
        self.wallet = wallet
        self.gap_limit = gap_limit

    def run(self):
        try:
            from .addresses import AddressImporter
            importer = AddressImporter(self.rpc, self.gap_limit)

            self.progress.emit(_("Importing addresses into Bitcoin Core…"))
            imported_new = importer.import_wallet(
                self.wallet,
                progress_cb=lambda msg: self.progress.emit(msg)
            )

            if imported_new:
                self.progress.emit(_("New addresses imported. Starting rescan… "
                                     "(this may take a long time on first run)"))
                self.rpc.rescanblockchain(0)
                self.progress.emit(_("Rescan complete."))
            else:
                self.progress.emit(_("All addresses already imported."))

            self.finished.emit(True, _("Import complete."))
        except Exception as e:
            logger.exception("Import worker error")
            self.finished.emit(False, str(e))


# ---------------------------------------------------------------------------
# The plugin itself
# ---------------------------------------------------------------------------

class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self._server = None
        self._server_running = False
        self._active_window: Optional["ElectrumWindow"] = None
        self._status_label: Optional[QLabel] = None

        # Cross-thread bridge for status updates. Created here (in the GUI
        # thread, since the plugin is constructed by Electrum's plugin system
        # on the main thread) so that the slot connection is also routed via
        # Qt::QueuedConnection when emit() comes from a non-GUI thread.
        self._status_bridge = _StatusBridge()
        self._status_bridge.status_changed.connect(self._apply_status_in_gui_thread)

        if self.config.get("eps_autostart", False):
            self._start_server_if_configured()

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    @hook
    def init_qt(self, gui):
        """Called once when the Qt GUI is ready."""
        self._gui = gui

    @hook
    def init_menubar(self, window: "ElectrumWindow"):
        """Add 'EPS Settings' entry to the Wallet menu."""
        window.wallet_menu.addAction("EPS Settings", lambda: self._open_settings_dialog(window))

    @hook
    def load_wallet(self, wallet: "Abstract_Wallet", window: "ElectrumWindow"):
        """Called each time a wallet is opened."""
        self._active_window = window
        self._active_wallet = wallet
        if self._server:
            self._register_wallet_addresses(wallet)
            # If start_server() ran before any window existed (e.g. autostart),
            # the bookmark op was deferred. Apply it now that we have a window.
            self._bookmark_eps_server(add=True)

    @hook
    def close_wallet(self, wallet: "Abstract_Wallet"):
        pass  # server keeps running; user must stop it explicitly

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _build_rpc(self):
        from .rpc import BitcoinRPC
        return BitcoinRPC(
            host=self.config.get("eps_rpc_host", "127.0.0.1"),
            port=int(self.config.get("eps_rpc_port", 8332)),
            user=self.config.get("eps_rpc_user", ""),
            password=self.config.get("eps_rpc_pass", ""),
            wallet=self.config.get("eps_rpc_wallet", ""),
        )

    def _start_server_if_configured(self):
        if not self.config.get("eps_rpc_user"):
            logger.info("EPS: not starting — RPC credentials not configured")
            return
        self.start_server()

    def start_server(self) -> bool:
        if self._server_running:
            return True

        try:
            rpc = self._build_rpc()
        except Exception as e:
            self._set_status(f"RPC init failed: {e}", error=True)
            return False
        try:
            rpc.getblockchaininfo()
        except Exception as e:
            self._set_status(f"Cannot connect to Bitcoin Core: {e}", error=True)
            return False

        cert_path = self.config.get("eps_cert_path", "")
        key_path = self.config.get("eps_key_path", "")
        if not cert_path or not key_path:
            from .tls import default_cert_paths, generate_self_signed_cert
            cert_path, key_path = default_cert_paths()
            if not generate_self_signed_cert(cert_path, key_path):
                self._set_status("TLS cert generation failed — running without TLS")
                cert_path = key_path = ""

        from .server import ElectrumServer
        self._server = ElectrumServer(
            rpc=rpc,
            host=self.config.get("eps_listen_host", "127.0.0.1"),
            port=int(self.config.get("eps_listen_port", 50002)),
            certfile=cert_path,
            keyfile=key_path,
        )
        self._server.on_client_connected = lambda peer: self._set_status(
            f"Client connected: {peer}")
        self._server.on_client_disconnected = lambda peer: self._set_status(
            f"Client disconnected: {peer}")

        self._server.start()
        self._server_running = True

        listen_host = self.config.get("eps_listen_host", "127.0.0.1")
        listen_port = self.config.get("eps_listen_port", 50002)
        scheme = "s" if (cert_path and key_path) else "t"
        self._eps_scheme = scheme

        # Make EPS discoverable in Electrum's Network preferences dialog
        # by adding it to NETWORK_BOOKMARKED_SERVERS. The user then chooses
        # to actually connect via the standard Network dialog. We never
        # override `server`, `oneserver`, or `auto_connect` — those remain
        # 100% the user's call.
        self._bookmark_eps_server(add=True)

        self._set_status(
            f"Running on {listen_host}:{listen_port} "
            f"(select it under Tools → Network)"
        )

        if hasattr(self, "_active_wallet") and self._active_wallet:
            self._register_wallet_addresses(self._active_wallet)

        return True

    def stop_server(self):
        # Remove the bookmark BEFORE stopping the server so that if the user
        # is currently connected through us, Electrum will fall back to its
        # normal server selection instead of repeatedly trying a dead bookmark.
        self._bookmark_eps_server(add=False)
        if self._server:
            self._server.stop()
            self._server = None
        self._server_running = False
        self._set_status("Stopped")

    def _eps_server_addr(self):
        """Build the ServerAddr describing our embedded server."""
        try:
            from electrum.interface import ServerAddr
        except ImportError:
            return None
        host = self.config.get("eps_listen_host", "127.0.0.1")
        port = int(self.config.get("eps_listen_port", 50002))
        scheme = getattr(self, "_eps_scheme", "s")
        try:
            return ServerAddr.from_str(f"{host}:{port}:{scheme}")
        except Exception as e:
            logger.warning(f"Could not build EPS ServerAddr: {e}")
            return None

    def _get_network(self):
        """Return Electrum's Network object, or None if not yet available."""
        win = getattr(self, "_active_window", None)
        return getattr(win, "network", None) if win else None

    def _bookmark_eps_server(self, *, add: bool) -> None:
        """Add or remove the EPS server from NETWORK_BOOKMARKED_SERVERS."""
        network = self._get_network()
        server = self._eps_server_addr()
        if network is None or server is None:
            # We may be called before a wallet/window has loaded.
            # In that case the bookmark op is deferred until load_wallet fires.
            logger.debug(
                f"Bookmark {'add' if add else 'remove'} deferred (no network yet)"
            )
            return
        try:
            network.set_server_bookmark(server, add=add)
            logger.info(f"{'Bookmarked' if add else 'Unbookmarked'} {server}")
        except Exception as e:
            logger.warning(f"Bookmark op failed: {e}")

    def _register_wallet_addresses(self, wallet):
        if not self._server:
            return
        addrs = list(wallet.get_addresses())
        for addr in addrs:
            self._server.register_address(addr)
        logger.info(
            f"EPS now tracking {len(self._server._scripthash_cache)} addresses "
            f"({len(addrs)} from {getattr(wallet, 'basename', lambda: '?')()})"
        )

    def _set_status(self, msg: str, error: bool = False):
        """
        Thread-safe: callable from any thread. Logs immediately and emits
        a Qt signal whose slot will run on the GUI thread to touch the
        QLabel widget.
        """
        logger.info(f"EPS status: {msg}")
        try:
            self._status_bridge.status_changed.emit(msg, error)
        except RuntimeError:
            # _status_bridge.deleteLater() happened (plugin unloaded) — drop.
            pass

    def _apply_status_in_gui_thread(self, msg: str, error: bool):
        """Slot — always runs in the GUI thread thanks to QueuedConnection."""
        label = self._status_label
        if label is None:
            return
        # Even on the GUI thread, the QLabel may have been destroyed in the
        # interval between emit() and the slot dispatch (dialog closed).
        try:
            color = "red" if error else "green"
            label.setText(msg)
            label.setStyleSheet(f"color: {color};")
        except RuntimeError:
            self._status_label = None

    # ------------------------------------------------------------------
    # Settings dialog (opened from Wallet menu)
    # ------------------------------------------------------------------

    def _open_settings_dialog(self, window: "ElectrumWindow"):
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox
        except ImportError:
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox

        dlg = QDialog(window)
        dlg.setWindowTitle("Electrum Personal Server")
        dlg.setMinimumWidth(480)
        layout = QVBoxLayout(dlg)
        layout.addWidget(self._settings_widget(dlg))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        # Drop the QLabel reference when the dialog closes — the widget
        # gets destroyed by Qt and any background thread that calls _set_status
        # afterwards would otherwise hit "wrapped C/C++ object has been deleted".
        dlg.finished.connect(lambda _: setattr(self, "_status_label", None))
        dlg.exec()

    # ------------------------------------------------------------------
    # Import addresses action
    # ------------------------------------------------------------------

    def import_wallet_addresses(self, window: "ElectrumWindow"):
        wallet = window.wallet
        if not wallet:
            QMessageBox.warning(window, "EPS", "No wallet open.")
            return

        rpc = self._build_rpc()
        gap_limit = int(self.config.get("eps_gap_limit", 20))

        dlg = QProgressDialog("Importing addresses…", None, 0, 0, window)
        dlg.setWindowModality(_WINDOW_MODAL)
        dlg.setWindowTitle("Electrum Personal Server")
        dlg.show()

        # Keep references on self so neither QThread nor worker get garbage-collected
        # while the worker is still running (would cause "QThread destroyed while running").
        self._import_thread = QThread()
        self._import_worker = ImportWorker(rpc, wallet, gap_limit)
        self._import_worker.moveToThread(self._import_thread)

        self._import_worker.progress.connect(dlg.setLabelText)

        def _on_finished(ok, msg):
            dlg.close()
            if ok:
                QMessageBox.information(window, "EPS", msg)
            else:
                QMessageBox.critical(window, "EPS", f"Import failed: {msg}")

        self._import_worker.finished.connect(_on_finished)
        self._import_thread.started.connect(self._import_worker.run)
        # When the worker is done: quit the thread loop, then schedule cleanup
        self._import_worker.finished.connect(self._import_thread.quit)
        self._import_thread.finished.connect(self._import_worker.deleteLater)
        self._import_thread.finished.connect(self._import_thread.deleteLater)

        self._import_thread.start()

    def _settings_widget(self, parent) -> QWidget:
        w = QWidget(parent)
        outer = QVBoxLayout(w)

        # ---- Status ----
        status_group = QGroupBox("Status")
        sg_layout = QHBoxLayout(status_group)
        self._status_label = QLabel("Not started")
        self._status_label.setStyleSheet("color: grey;")
        sg_layout.addWidget(self._status_label)

        btn_start = QPushButton("Start")
        btn_stop = QPushButton("Stop")
        btn_start.clicked.connect(lambda: self.start_server())
        btn_stop.clicked.connect(lambda: self.stop_server())
        sg_layout.addWidget(btn_start)
        sg_layout.addWidget(btn_stop)
        outer.addWidget(status_group)

        # ---- Bitcoin Core RPC ----
        rpc_group = QGroupBox("Bitcoin Core RPC")
        rg = QVBoxLayout(rpc_group)

        def row(label, key, default, *, password=False):
            h = QHBoxLayout()
            h.addWidget(QLabel(label))
            edit = QLineEdit(str(self.config.get(key, default)))
            if password:
                edit.setEchoMode(_ECHO_PASSWORD)
            edit.textChanged.connect(lambda v: self.config.set_key(key, v))
            h.addWidget(edit)
            rg.addLayout(h)
            return edit

        row("Host:", "eps_rpc_host", "127.0.0.1")
        row("Port:", "eps_rpc_port", 8332)
        row("Username:", "eps_rpc_user", "")
        row("Password:", "eps_rpc_pass", "", password=True)
        row("Wallet (optional):", "eps_rpc_wallet", "")

        rpc_group.setLayout(rg)
        outer.addWidget(rpc_group)

        # ---- Server settings ----
        srv_group = QGroupBox("Server")
        sg = QVBoxLayout(srv_group)

        h = QHBoxLayout()
        h.addWidget(QLabel("Listen host:"))
        listen_host_edit = QLineEdit(self.config.get("eps_listen_host", "127.0.0.1"))
        listen_host_edit.textChanged.connect(
            lambda v: self.config.set_key("eps_listen_host", v))
        h.addWidget(listen_host_edit)
        sg.addLayout(h)

        h = QHBoxLayout()
        h.addWidget(QLabel("Listen port:"))
        port_spin = QSpinBox()
        port_spin.setRange(1024, 65535)
        port_spin.setValue(int(self.config.get("eps_listen_port", 50002)))
        port_spin.valueChanged.connect(
            lambda v: self.config.set_key("eps_listen_port", v))
        h.addWidget(port_spin)
        sg.addLayout(h)

        h = QHBoxLayout()
        h.addWidget(QLabel("Gap limit:"))
        gap_spin = QSpinBox()
        gap_spin.setRange(5, 200)
        gap_spin.setValue(int(self.config.get("eps_gap_limit", 20)))
        gap_spin.valueChanged.connect(
            lambda v: self.config.set_key("eps_gap_limit", v))
        h.addWidget(gap_spin)
        sg.addLayout(h)

        autostart_cb = QCheckBox("Start server automatically on plugin enable")
        autostart_cb.setChecked(bool(self.config.get("eps_autostart", False)))
        autostart_cb.stateChanged.connect(
            lambda v: self.config.set_key("eps_autostart", bool(v)))
        sg.addWidget(autostart_cb)

        outer.addWidget(srv_group)

        # ---- TLS ----
        tls_group = QGroupBox("TLS Certificate")
        tg = QVBoxLayout(tls_group)

        from .tls import default_cert_paths
        default_cert, default_key = default_cert_paths()

        def path_row(label, key, default):
            h = QHBoxLayout()
            h.addWidget(QLabel(label))
            edit = QLineEdit(self.config.get(key, default))
            edit.textChanged.connect(lambda v: self.config.set_key(key, v))
            btn = QPushButton("…")
            btn.setMaximumWidth(30)
            btn.clicked.connect(lambda: (
                edit.setText(QFileDialog.getOpenFileName(
                    parent, f"Select {label}", "",
                    "PEM files (*.pem *.crt *.key);;All (*)"
                )[0] or edit.text())
            ))
            h.addWidget(edit)
            h.addWidget(btn)
            tg.addLayout(h)

        path_row("Certificate:", "eps_cert_path", default_cert)
        path_row("Key:", "eps_key_path", default_key)

        btn_gen = QPushButton("Generate self-signed certificate")
        def _gen():
            from .tls import generate_self_signed_cert
            cert = self.config.get("eps_cert_path", default_cert)
            key  = self.config.get("eps_key_path", default_key)
            if generate_self_signed_cert(cert, key):
                QMessageBox.information(parent, "EPS", f"Certificate generated:\n{cert}")
            else:
                QMessageBox.critical(parent, "EPS",
                    "Failed to generate certificate.\n"
                    "Ensure `openssl` is on PATH or install the `cryptography` package.")
        btn_gen.clicked.connect(_gen)
        tg.addWidget(btn_gen)
        outer.addWidget(tls_group)

        # ---- Address import ----
        imp_group = QGroupBox("Wallet Import")
        ig = QVBoxLayout(imp_group)
        ig.addWidget(QLabel(
            "Import your wallet's addresses into Bitcoin Core.\n"
            "Required once per wallet. A rescan will be triggered on first import."
        ))
        btn_import = QPushButton("Import addresses from open wallet")
        btn_import.clicked.connect(
            lambda: self.import_wallet_addresses(parent.parent()))
        ig.addWidget(btn_import)
        outer.addWidget(imp_group)

        outer.addStretch()
        return w

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self):
        self.stop_server()
        bridge = getattr(self, "_status_bridge", None)
        if bridge is not None:
            try:
                bridge.deleteLater()
            except RuntimeError:
                pass
            self._status_bridge = None
        BasePlugin.close(self)
