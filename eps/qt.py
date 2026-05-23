# eps/qt.py
#
# Electrum plugin entry point for the Qt GUI.
# Manages the server lifecycle, settings UI, and wallet hooks.

import logging
from typing import Optional, TYPE_CHECKING
from urllib.parse import urlparse
from xml.sax.saxutils import escape

try:
    from PyQt6.QtWidgets import (
        QFormLayout, QLabel,
        QLineEdit, QMessageBox, QProgressDialog, QPushButton, QSpinBox,
        QTextEdit, QVBoxLayout,
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
    from PyQt6.QtGui import QTextOption
    _ECHO_PASSWORD = QLineEdit.EchoMode.Password
    _WINDOW_MODAL = Qt.WindowModality.WindowModal
    _ALIGN_RIGHT_VCENTER = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
    _WRAP_ANYWHERE = QTextOption.WrapMode.WrapAnywhere
except ImportError:
    from PyQt5.QtWidgets import (
        QFormLayout, QLabel,
        QLineEdit, QMessageBox, QProgressDialog, QPushButton, QSpinBox,
        QTextEdit, QVBoxLayout,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
    from PyQt5.QtGui import QTextOption
    _ECHO_PASSWORD = QLineEdit.Password
    _WINDOW_MODAL = Qt.WindowModal
    _ALIGN_RIGHT_VCENTER = Qt.AlignRight | Qt.AlignVCenter
    _WRAP_ANYWHERE = QTextOption.WrapAnywhere

from electrum import constants
from electrum.gui.qt.util import Buttons, CloseButton, WindowModalDialog
from electrum.i18n import _
from electrum.plugin import BasePlugin, hook

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qt.main_window import ElectrumWindow

logger = logging.getLogger("eps.plugin")

_LOG_COLORS = {
    'ERROR': '#CD0200',
    'WARN': '#D47500',
    'INFO': '#4BBF73',
    'DEBUG': '#2780E3',
}


def default_rpc_port() -> int:
    return {
        'mainnet': 8332,
        'testnet': 18332,
        'testnet4': 48332,
        'regtest': 18443,
        'signet': 38332,
    }.get(constants.net.NET_NAME, 8332)


def default_rpc_url() -> str:
    return f"http://127.0.0.1:{default_rpc_port()}/"


def _compose_rpc_url(host: str, port) -> str:
    return f"http://{host}:{port}/"


def _parse_rpc_url(url: str) -> tuple:
    url = (url or "").strip()
    if not url:
        return "127.0.0.1", default_rpc_port()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or default_rpc_port()
    return host, int(port)


def _parse_rpc_auth(auth: str) -> tuple:
    auth = (auth or "").strip()
    if not auth:
        return "", ""
    user, _, password = auth.partition(":")
    return user, password


def _compose_rpc_auth(user: str, password: str) -> str:
    if not user:
        return ""
    return f"{user}:{password}"


def title(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet('QLabel { font-weight: bold }')
    return label


def helptext(text: str, wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(wrap)
    label.setStyleSheet('QLabel { color: #aaa; font-size: 0.9em }')
    return label


def input_field(value=None, width: int = 400) -> QLineEdit:
    edit = QLineEdit()
    if value is not None:
        edit.setText(str(value))
    edit.setMaximumWidth(width)
    return edit


def append_log(log_t: QTextEdit, level: str, pkg: str, msg: str) -> None:
    scrollbar = log_t.verticalScrollBar()
    was_on_bottom = scrollbar.value() >= scrollbar.maximum() - 5
    color = _LOG_COLORS.get(level, 'auto')
    log_t.append(
        f'<p><span style="color:{color}">{escape(level)}</span> '
        f'<strong>{escape(pkg)}</strong> » {escape(msg)}</p>'
    )
    log_t.show()
    if was_on_bottom:
        log_t.ensureCursorVisible()


# ---------------------------------------------------------------------------
# Thread-safe bridge for GUI updates from background threads
# ---------------------------------------------------------------------------

class _StatusBridge(QObject):
    status_changed = pyqtSignal(str, bool)   # (message, is_error)
    log_line = pyqtSignal(str, str, str)     # (level, pkg, msg)


# ---------------------------------------------------------------------------
# Worker thread for import + rescan (keeps GUI responsive)
# ---------------------------------------------------------------------------

class ImportWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

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
                progress_cb=lambda msg: self.progress.emit(msg),
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
        self._active_wallet: Optional["Abstract_Wallet"] = None
        self._status_label: Optional[QLabel] = None
        self._log_widget: Optional[QTextEdit] = None
        self._prev_network_settings = None
        self._eps_scheme = "s"

        self._status_bridge = _StatusBridge()
        self._status_bridge.status_changed.connect(self._apply_status_in_gui_thread)
        self._status_bridge.log_line.connect(self._apply_log_in_gui_thread)

    # ------------------------------------------------------------------
    # Plugin settings entry (Tools → Plugins → Settings)
    # ------------------------------------------------------------------

    def requires_settings(self):
        return True

    def settings_dialog(self, window):
        """Opened from Tools → Plugins, or via Wallet → EPS Settings."""
        self._open_settings_dialog(window)

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    @hook
    def init_menubar(self, window: "ElectrumWindow"):
        window.wallet_menu.addAction(
            "EPS Settings", lambda: self.settings_dialog(window))

    @hook
    def load_wallet(self, wallet: "Abstract_Wallet", window: "ElectrumWindow"):
        self._active_window = window
        self._active_wallet = wallet
        if not self._server_running:
            if not self.config.get("eps_rpc_user"):
                logger.info("EPS: wallet opened but RPC not configured")
                return
            if not self.start_server():
                return
            return
        self._register_wallet_addresses(wallet)
        self._bookmark_eps_server(add=True)
        if self._prev_network_settings is not None:
            self._auto_configure_network()

    @hook
    def close_wallet(self, wallet: "Abstract_Wallet"):
        pass

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _build_rpc(self):
        from .rpc import BitcoinRPC
        return BitcoinRPC(
            host=self.config.get("eps_rpc_host", "127.0.0.1"),
            port=int(self.config.get("eps_rpc_port", default_rpc_port())),
            user=self.config.get("eps_rpc_user", ""),
            password=self.config.get("eps_rpc_pass", ""),
            wallet=self.config.get("eps_rpc_wallet", ""),
        )

    def _tls_cert_paths(self) -> tuple:
        """Return (certfile, keyfile), auto-generating a self-signed cert if needed."""
        from .tls import default_cert_paths, generate_self_signed_cert
        cert_path, key_path = default_cert_paths()
        if not generate_self_signed_cert(cert_path, key_path):
            self._set_status("TLS cert generation failed — running without TLS", error=True)
            return "", ""
        return cert_path, key_path

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

        cert_path, key_path = self._tls_cert_paths()

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
        self._eps_scheme = "s" if (cert_path and key_path) else "t"

        self._bookmark_eps_server(add=True)
        self._auto_configure_network()

        self._set_status(f"Running on {listen_host}:{listen_port}")

        if self._active_wallet:
            self._register_wallet_addresses(self._active_wallet)

        return True

    def stop_server(self):
        self._bookmark_eps_server(add=False)
        if self._server:
            self._server.on_client_connected = None
            self._server.on_client_disconnected = None
            self._server.stop()
            self._server = None
        self._server_running = False
        self._set_status("Stopped")

    def _emit_log(self, level: str, pkg: str, msg: str) -> None:
        bridge = getattr(self, "_status_bridge", None)
        if bridge is None:
            return
        try:
            bridge.log_line.emit(level, pkg, msg)
        except RuntimeError:
            pass

    def _emit_status(self, msg: str, error: bool) -> None:
        bridge = getattr(self, "_status_bridge", None)
        if bridge is None:
            return
        try:
            bridge.status_changed.emit(msg, error)
        except RuntimeError:
            pass

    def _eps_server_addr(self):
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
        win = getattr(self, "_active_window", None)
        return getattr(win, "network", None) if win else None

    def _prepare_network_override(self):
        if self._prev_network_settings is not None:
            return
        self._prev_network_settings = {
            setting: self.config.cmdline_options.get(setting)
            for setting in ("oneserver", "server")
        }
        self.config.cmdline_options["oneserver"] = True
        self.config.cmdline_options.setdefault("server", "127.0.0.1:1:t")

    def _auto_configure_network(self):
        try:
            from electrum.network import Network
        except ImportError:
            return

        network = Network.get_instance() or self._get_network()
        server = self._eps_server_addr()
        if network is None or server is None:
            logger.debug("Network auto-config deferred (no network or server yet)")
            return

        self._prepare_network_override()
        self.config.cmdline_options.pop("server", None)

        try:
            net_params = network.get_parameters()._replace(
                server=server, oneserver=True)
            network.run_from_another_thread(network.set_parameters(net_params))
            self.config.cmdline_options["server"] = str(server)
            self._log("INFO", f"Electrum network set to {server}")
        except Exception as e:
            logger.warning(f"Network auto-config failed: {e}")
            self._log("WARN", f"Could not auto-configure network: {e}")

    def _restore_network_settings(self):
        if not self._prev_network_settings:
            return
        for setting, prev_value in self._prev_network_settings.items():
            if prev_value is None:
                self.config.cmdline_options.pop(setting, None)
            else:
                self.config.cmdline_options[setting] = prev_value
        self._prev_network_settings = None

    def _bookmark_eps_server(self, *, add: bool) -> None:
        network = self._get_network()
        server = self._eps_server_addr()
        if network is None or server is None:
            logger.debug(
                f"Bookmark {'add' if add else 'remove'} deferred (no network yet)")
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

    def _log(self, level: str, msg: str, *, pkg: str = "eps"):
        logger.log(getattr(logging, level, logging.INFO), msg)
        self._emit_log(level, pkg, msg)

    def _set_status(self, msg: str, error: bool = False):
        level = "ERROR" if error else "INFO"
        self._log(level, msg)
        self._emit_status(msg, error)

    def _apply_status_in_gui_thread(self, msg: str, error: bool):
        label = self._status_label
        if label is None:
            return
        try:
            color = "red" if error else "green"
            label.setText(msg)
            label.setStyleSheet(f"color: {color};")
        except RuntimeError:
            self._status_label = None

    def _apply_log_in_gui_thread(self, level: str, pkg: str, msg: str):
        log_t = self._log_widget
        if log_t is None:
            return
        try:
            append_log(log_t, level, pkg, msg)
        except RuntimeError:
            self._log_widget = None

    # ------------------------------------------------------------------
    # Settings dialog
    # ------------------------------------------------------------------

    def _open_settings_dialog(self, window):
        d = WindowModalDialog(window, _('Connect to Bitcoin Core with EPS'))
        d.setMinimumWidth(570)
        vbox = QVBoxLayout(d)

        warnings = []
        if not self._active_wallet:
            warnings.append(_("No wallet is open. You can configure EPS now; "
                              "import and sync require a wallet."))
        if not self.config.get("eps_rpc_user"):
            warnings.append(_("RPC username is not configured yet."))

        for text in warnings:
            vbox.addWidget(helptext(text, True))

        form = QFormLayout()
        form.setLabelAlignment(_ALIGN_RIGHT_VCENTER)
        vbox.addLayout(form)

        # --- Bitcoin Core settings ---
        form.addRow(title(_('Bitcoin Core settings')))

        rpc_host = self.config.get("eps_rpc_host", "127.0.0.1")
        rpc_port = self.config.get("eps_rpc_port", default_rpc_port())
        url_e = input_field(_compose_rpc_url(rpc_host, rpc_port))
        form.addRow(_('RPC URL:'), url_e)

        auth_e = input_field(_compose_rpc_auth(
            self.config.get("eps_rpc_user", ""),
            self.config.get("eps_rpc_pass", ""),
        ))
        auth_e.setPlaceholderText('<username>:<password>')
        auth_e.setEchoMode(_ECHO_PASSWORD)
        form.addRow(_('RPC Auth:'), auth_e)
        form.addRow('', helptext(_('Required. Bitcoin Core rpcuser/rpcpassword.'), False))

        dir_e = input_field(self.config.get("eps_rpc_datadir", ""))
        form.addRow(_('Directory:'), dir_e)
        form.addRow('', helptext(
            _('Bitcoin Core datadir (for cookie auth). Not used when RPC Auth is set.'),
            False))

        wallet_e = input_field(self.config.get("eps_rpc_wallet", ""), 150)
        form.addRow(_('Wallet:'), wallet_e)
        form.addRow('', helptext(
            _('Optional named Core wallet (e.g. eps-test). Leave blank for default.'),
            False))

        # --- EPS server settings ---
        form.addRow(title(_('EPS server settings')))

        listen_host_e = input_field(self.config.get("eps_listen_host", "127.0.0.1"), 150)
        form.addRow(_('Listen host:'), listen_host_e)

        listen_port_e = QSpinBox()
        listen_port_e.setRange(1024, 65535)
        listen_port_e.setValue(int(self.config.get("eps_listen_port", 50002)))
        listen_port_e.setMaximumWidth(150)
        form.addRow(_('Listen port:'), listen_port_e)

        gap_e = QSpinBox()
        gap_e.setRange(5, 200)
        gap_e.setValue(int(self.config.get("eps_gap_limit", 20)))
        gap_e.setMaximumWidth(150)
        form.addRow(_('Gap limit:'), gap_e)
        form.addRow('', helptext(
            _('Addresses beyond the last used to import into Core on bulk import.'),
            False))

        # --- Wallet import ---
        form.addRow(title(_('Wallet import')))
        import_btn = QPushButton(_('Import addresses from open wallet'))
        form.addRow('', import_btn)
        form.addRow('', helptext(
            _('Required once per wallet. Triggers a Core rescan on first import.'),
            False))

        # --- Status / log ---
        form.addRow(title(_('Status')))

        self._status_label = QLabel(
            _("Running") if self._server_running else _("Not started"))
        self._status_label.setStyleSheet(
            "color: green;" if self._server_running else "color: grey;")
        form.addRow('', self._status_label)

        log_t = QTextEdit()
        log_t.setReadOnly(True)
        log_t.setFixedHeight(80)
        log_t.setStyleSheet('QTextEdit { color: #888; font-size: 0.9em }')
        log_t.setWordWrapMode(_WRAP_ANYWHERE)
        log_t.hide()
        form.addRow(log_t)
        self._log_widget = log_t

        def _apply_form_to_config():
            host, port = _parse_rpc_url(url_e.text())
            user, password = _parse_rpc_auth(auth_e.text())
            self.config.set_key("eps_rpc_host", host)
            self.config.set_key("eps_rpc_port", port)
            self.config.set_key("eps_rpc_user", user)
            self.config.set_key("eps_rpc_pass", password)
            self.config.set_key("eps_rpc_datadir", dir_e.text().strip())
            self.config.set_key("eps_rpc_wallet", wallet_e.text().strip())
            self.config.set_key("eps_listen_host", listen_host_e.text().strip())
            self.config.set_key("eps_listen_port", listen_port_e.value())
            self.config.set_key("eps_gap_limit", gap_e.value())

        def _can_connect() -> bool:
            user, password = _parse_rpc_auth(auth_e.text())
            return bool(user and password)

        def _save_and_connect():
            if not _can_connect():
                QMessageBox.warning(
                    d, "EPS",
                    _("RPC Auth is required (username:password)."))
                return
            _apply_form_to_config()
            log_t.clear()
            log_t.show()
            if self._server_running:
                self.stop_server()
            if self.start_server():
                self._log("INFO", "Save & Connect completed")
            else:
                self._log("ERROR", "Failed to start EPS server")

        save_b = QPushButton(_('Save && Connect'))
        save_b.setDefault(True)
        save_b.clicked.connect(_save_and_connect)

        import_btn.clicked.connect(
            lambda: self.import_wallet_addresses(self._active_window, d))

        if not self._active_wallet:
            import_btn.setEnabled(False)

        vbox.addLayout(Buttons(CloseButton(d), save_b))

        def _cleanup():
            self._status_label = None
            self._log_widget = None

        d.finished.connect(lambda _: _cleanup())
        if hasattr(d, 'exec'):
            d.exec()
        else:
            d.exec_()

    # ------------------------------------------------------------------
    # Import addresses action
    # ------------------------------------------------------------------

    def import_wallet_addresses(self, window, parent=None):
        if window is None or not getattr(window, "wallet", None):
            QMessageBox.warning(
                parent or window or self._active_window,
                "EPS", _("No wallet open."))
            return

        wallet = window.wallet
        rpc = self._build_rpc()
        gap_limit = int(self.config.get("eps_gap_limit", 20))

        dlg = QProgressDialog(_("Importing addresses…"), None, 0, 0, window)
        dlg.setWindowModality(_WINDOW_MODAL)
        dlg.setWindowTitle("Electrum Personal Server")
        dlg.show()

        self._import_thread = QThread()
        self._import_worker = ImportWorker(rpc, wallet, gap_limit)
        self._import_worker.moveToThread(self._import_thread)

        def _on_progress(msg):
            dlg.setLabelText(msg)
            self._log("INFO", msg)

        self._import_worker.progress.connect(_on_progress)

        def _on_finished(ok, msg):
            dlg.close()
            if ok:
                QMessageBox.information(window, "EPS", msg)
                self._log("INFO", msg)
            else:
                QMessageBox.critical(window, "EPS", f"Import failed: {msg}")
                self._log("ERROR", msg)

        self._import_worker.finished.connect(_on_finished)
        self._import_thread.started.connect(self._import_worker.run)
        self._import_worker.finished.connect(self._import_thread.quit)
        self._import_thread.finished.connect(self._import_worker.deleteLater)
        self._import_thread.finished.connect(self._import_thread.deleteLater)
        self._import_thread.start()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self):
        self.stop_server()
        self._restore_network_settings()
        bridge = getattr(self, "_status_bridge", None)
        if bridge is not None:
            try:
                bridge.deleteLater()
            except RuntimeError:
                pass
            self._status_bridge = None
        BasePlugin.close(self)
