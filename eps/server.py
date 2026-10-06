# eps_plugin/server.py
#
# Implements the Electrum server protocol (ElectrumX/EPS flavour) over a
# TLS TCP socket, backed entirely by Bitcoin Core RPC calls.
#
# Threading model:
#   - One thread per client connection (simple; EPS is single-user)
#   - The main server loop runs in a dedicated daemon thread
#   - All RPC calls are blocking (no asyncio needed at this scale)
#
# Electrum protocol reference:
#   https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-methods.html

import json
import socket
import ssl
import threading
import hashlib
import time
import logging
from typing import Dict, List, Optional, Callable, Any, Tuple

from .rpc import BitcoinRPC, RPCError
from .addresses import scriptpubkey_to_scripthash, ScriptWatcher

logger = logging.getLogger("eps.server")

# Protocol 1.7 only: clients send scriptPubKeys directly, so the server
# needs no wallet knowledge. Older protocols query by scripthash (a one-way
# hash), which would require pre-registering wallet addresses.
PROTOCOL_VERSION_MIN = "1.7"
PROTOCOL_VERSION_MAX = "1.7"
PROTOCOL_VERSION = PROTOCOL_VERSION_MIN  # default for legacy callers
SERVER_VERSION = "EPS-plugin/0.1.0"
BLOCK_HEADERS_MAX = 2016


def _protocol_tuple(version: str) -> tuple:
    major, minor = version.split(".", 1)
    return int(major), int(minor)


def _negotiate_protocol(client_version) -> str:
    """Pick the highest protocol version supported by both sides."""
    s_min = _protocol_tuple(PROTOCOL_VERSION_MIN)
    s_max = _protocol_tuple(PROTOCOL_VERSION_MAX)
    if isinstance(client_version, (list, tuple)) and len(client_version) >= 2:
        c_min = _protocol_tuple(str(client_version[0]))
        c_max = _protocol_tuple(str(client_version[1]))
    elif isinstance(client_version, str):
        c_min = c_max = _protocol_tuple(client_version)
    else:
        c_min = c_max = s_min
    mutual_lo = max(c_min, s_min)
    mutual_hi = min(c_max, s_max)
    if mutual_lo > mutual_hi:
        raise ElectrumServerError("unsupported protocol version")
    return f"{mutual_hi[0]}.{mutual_hi[1]}"


class ElectrumServerError(Exception):
    pass


def _merkle_branch(txids: List[str], pos: int) -> List[str]:
    """
    Compute the Merkle branch for the transaction at `pos` in a block
    whose transaction list is `txids`.

    The branch is the list of sibling hashes needed to verify the tx
    against the Merkle root, ordered from leaf to root.
    Each hash is a hex string in display byte-order (little-endian on wire,
    shown reversed — same as txids).
    """
    def hash_pair(a: str, b: str) -> str:
        # Electrum/Bitcoin txid strings are in reversed-bytes display order;
        # convert to raw bytes, double-SHA256, reverse back.
        raw_a = bytes.fromhex(a)[::-1]
        raw_b = bytes.fromhex(b)[::-1]
        digest = hashlib.sha256(hashlib.sha256(raw_a + raw_b).digest()).digest()
        return digest[::-1].hex()

    hashes = list(txids)
    branch = []
    idx = pos
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])   # duplicate last hash if odd count
        sibling = idx ^ 1               # XOR flips the last bit to get sibling
        branch.append(hashes[sibling])
        next_level = []
        for i in range(0, len(hashes), 2):
            next_level.append(hash_pair(hashes[i], hashes[i + 1]))
        hashes = next_level
        idx //= 2
    return branch


# ---------------------------------------------------------------------------
# Wallet transaction index
# ---------------------------------------------------------------------------

class _IndexedTx:
    __slots__ = ("spks", "height", "fee_sats")

    def __init__(self, spks: set):
        self.spks = spks
        # Block height; 0 = mempool, -1 = mempool with an unconfirmed parent.
        self.height: int = 0
        # Mempool txs only (the protocol requires a fee on mempool entries).
        self.fee_sats: Optional[int] = None


class WalletTxIndex:
    """
    Incremental index of the Core wallet's transactions, keyed by every
    scriptPubKey they touch (all outputs plus the prevouts they spend).

    Every script a client queries is imported into the Core wallet first
    (ScriptWatcher.ensure_watched), so a script's Electrum history is exactly
    the set of wallet transactions that pay to it or spend from it. No Core
    RPC answers that directly: listsinceblock / listtransactions report
    'send' entries under the *destination* address and omit change outputs
    altogether, so a spend can never be attributed to the script it spent
    from that way. This index decodes each wallet tx once (gettransaction,
    which works without -txindex and on pruned nodes) and does the
    attribution itself.

    Refreshes are incremental: listsinceblock(<last seen block>) returns the
    txs confirmed since then plus everything still unconfirmed, so the
    steady-state cost is O(unconfirmed wallet txs) per refresh regardless of
    wallet size. The first refresh decodes the whole wallet once.

    Known limitation (shared with the original EPS): a tx that was already in
    the mempool before its script was imported into the wallet is not seen
    until it confirms.
    """

    TTL = 2.0  # seconds; one refresh serves a whole burst of subscriptions

    def __init__(self, rpc: BitcoinRPC):
        self.rpc = rpc
        self._lock = threading.Lock()
        self._last_refresh = 0.0
        self._last_block = ""   # listsinceblock cursor; "" = full scan
        self._txs: Dict[str, _IndexedTx] = {}
        self._spk_to_txids: Dict[str, set] = {}

    def history_for_spk(self, spk_hex: str) -> List[Tuple[str, int, Optional[int]]]:
        """(txid, height, fee_sats) for every wallet tx touching `spk_hex`.

        height > 0 is a confirmed block height; 0 / -1 is mempool, with
        fee_sats set when Core reported one. Refreshes the index if stale.
        """
        spk_hex = spk_hex.lower()
        with self._lock:
            self._maybe_refresh()
            return [(txid, self._txs[txid].height, self._txs[txid].fee_sats)
                    for txid in self._spk_to_txids.get(spk_hex, ())]

    # -- refresh -------------------------------------------------------

    def _maybe_refresh(self):
        now = time.monotonic()
        if now - self._last_refresh < self.TTL:
            return
        self._last_refresh = now
        try:
            self._refresh()
        except RPCError as e:
            logger.warning(f"wallet index: refresh failed, will resync: {e}")
            self._last_block = ""

    def _refresh(self):
        result = self.rpc.call("listsinceblock", self._last_block, 1, True, True)
        # listsinceblock yields one entry per (tx, address, category);
        # collapse to one per txid — the height fields are identical.
        entries: Dict[str, dict] = {}
        for e in result.get("transactions", []):
            entries.setdefault(e["txid"], e)
        if not self._last_block and len(entries) > 200:
            logger.info(f"wallet index: indexing {len(entries)} wallet transactions…")

        complete = True
        tip: Optional[int] = None
        for txid, e in entries.items():
            confs = e.get("confirmations", 0)
            if confs < 0:                       # conflicted
                self._evict(txid)
                continue
            if confs == 0:
                mem = self._mempool_info(txid)
                if mem is None:                 # abandoned / replaced / dropped
                    self._evict(txid)
                    continue
                height, fee = mem
            else:
                height = e.get("blockheight")
                if height is None:              # Core < 0.20
                    if tip is None:
                        tip = self.rpc.getblockcount()
                    height = tip - confs + 1
                fee = None

            tx = self._txs.get(txid)
            if tx is None:
                spks = self._spks_touched(txid, confirmed=confs > 0)
                if spks is None:
                    complete = False            # transient failure: retry next refresh
                    continue
                tx = self._txs[txid] = _IndexedTx(spks)
                for spk in spks:
                    self._spk_to_txids.setdefault(spk, set()).add(txid)
            tx.height, tx.fee_sats = height, fee

        # Txs in blocks that were reorged out and did not come back.
        for e in result.get("removed", []):
            if e["txid"] not in entries:
                self._evict(e["txid"])
        # Unconfirmed txs are reported on every call; any we knew that no
        # longer appear were purged from the wallet.
        for txid, tx in list(self._txs.items()):
            if tx.height <= 0 and txid not in entries:
                self._evict(txid)

        # Only move the cursor forward once every tx in this window is
        # indexed, so a transient decode failure is retried rather than lost.
        if complete and result.get("lastblock"):
            self._last_block = result["lastblock"]

    def _evict(self, txid: str):
        tx = self._txs.pop(txid, None)
        if tx is None:
            return
        for spk in tx.spks:
            txids = self._spk_to_txids.get(spk)
            if txids is not None:
                txids.discard(txid)
                if not txids:
                    del self._spk_to_txids[spk]

    # -- per-tx lookups ------------------------------------------------

    def _mempool_info(self, txid: str) -> Optional[Tuple[int, Optional[int]]]:
        """(height, fee_sats) for a mempool tx, or None if it isn't in the mempool."""
        try:
            entry = self.rpc.call("getmempoolentry", txid)
        except RPCError:
            return None
        # Core returns fees in BTC under 'fees.base' (modern) or 'fee' (old).
        fees = entry.get("fees") or {}
        fee_btc = fees.get("base", entry.get("fee"))
        fee_sats = int(round(fee_btc * 1e8)) if fee_btc is not None else None
        # Electrum: -1 if any input is still unconfirmed, 0 otherwise.
        height = -1 if entry.get("ancestorcount", 1) > 1 else 0
        return height, fee_sats

    def _spks_touched(self, txid: str, *, confirmed: bool) -> Optional[set]:
        """Scripts paid to, or spent from, by wallet tx `txid`; None on RPC failure."""
        try:
            tx = self.rpc.call("gettransaction", txid, True, True)
        except RPCError as e:
            logger.debug(f"wallet index: gettransaction {txid} failed: {e}")
            return None
        decoded = tx.get("decoded") or {}
        spks = set()
        for vout in decoded.get("vout", []):
            spk = vout.get("scriptPubKey", {}).get("hex", "")
            if spk:
                spks.add(spk.lower())
        # gettransaction only reports 'fee' when the wallet funded at least
        # one input. Without it no input is ours as far as the wallet knows,
        # and the only way one could still be a watched script is a mempool
        # tx spending a prevout imported too recently for the wallet to know
        # about it — so confirmed txs skip the (failing) per-input lookups.
        if "fee" in tx or not confirmed:
            for vin in decoded.get("vin", []):
                prev_txid, prev_n = vin.get("txid"), vin.get("vout")
                if prev_txid is None or prev_n is None:
                    continue   # coinbase
                spk = self._prevout_spk(prev_txid, prev_n, deep=not confirmed)
                if spk:
                    spks.add(spk)
        return spks

    def _prevout_spk(self, prev_txid: str, prev_n: int, *, deep: bool) -> Optional[str]:
        # Inputs the wallet owns have their parent in the wallet; this works
        # without -txindex and for pruned blocks.
        try:
            parent = self.rpc.call("gettransaction", prev_txid, True, True)
            return self._vout_spk(parent.get("decoded") or {}, prev_n)
        except (RPCError, KeyError, IndexError, TypeError):
            pass
        if not deep:
            return None
        # Confirmed prevout still in the UTXO set (include_mempool=False so
        # the pending spend doesn't hide it) — works without txindex.
        try:
            txout = self.rpc.call("gettxout", prev_txid, prev_n, False)
        except RPCError:
            txout = None
        if txout:
            spk = txout.get("scriptPubKey", {}).get("hex", "").lower()
            if spk:
                return spk
        # Unconfirmed parent (or a txindex node): fall back to the raw tx.
        try:
            return self._vout_spk(self.rpc.getrawtransaction(prev_txid, True), prev_n)
        except (RPCError, KeyError, IndexError, TypeError):
            return None

    @staticmethod
    def _vout_spk(decoded: dict, n: int) -> Optional[str]:
        spk = decoded["vout"][n].get("scriptPubKey", {}).get("hex", "")
        return spk.lower() or None


# ---------------------------------------------------------------------------
# Subscription state per-client
# ---------------------------------------------------------------------------

class ClientState:
    def __init__(self):
        self.protocol_version: str = PROTOCOL_VERSION_MIN
        self.scriptpubkey_subs: set = set()   # spk hex strings
        self.outpoint_subs: set = set()       # (txid, vout) tuples
        self.headers_sub: bool = False
        self.write_lock: threading.Lock = threading.Lock()


# ---------------------------------------------------------------------------
# The actual server
# ---------------------------------------------------------------------------

class ElectrumServer:
    """
    Listens on a TLS TCP port and speaks the Electrum protocol.

    Usage:
        server = ElectrumServer(rpc, host, port, certfile, keyfile)
        server.start()   # spawns daemon thread
        ...
        server.stop()
    """

    def __init__(self, rpc: BitcoinRPC, host: str = "127.0.0.1",
                 port: int = 50002, certfile: str = "", keyfile: str = ""):
        self.rpc = rpc
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._server_sock: Optional[socket.socket] = None

        # Cache last known block height + hash for header subscriptions
        self._tip_height: int = 0
        self._tip_hash: str = ""
        self._tip_lock = threading.Lock()

        # Active client connections: {thread -> (conn, state)}
        self._clients: Dict[threading.Thread, tuple] = {}
        self._clients_lock = threading.Lock()

        self._script_watcher = ScriptWatcher(rpc)
        self._wallet_index = WalletTxIndex(rpc)

        # Last pushed subscription status (spk hex -> status or None)
        self._status_cache: Dict[str, Optional[str]] = {}

        # Notification callbacks set by qt.py (so the GUI can update status)
        self.on_client_connected: Optional[Callable[[str], None]] = None
        self.on_client_disconnected: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        # Bind + listen synchronously so a port conflict (e.g. an original
        # EPS instance, which uses the same default port) fails loudly here
        # instead of killing a daemon thread after start() returned success.
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(5)
        raw_sock.settimeout(1.0)   # so the accept loop can check _stop_event
        self._server_sock = raw_sock

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="eps-server-main")
        self._thread.start()
        # Background thread that polls for new blocks and notifies subscribers
        self._notifier = threading.Thread(target=self._notification_loop,
                                          daemon=True, name="eps-notifier")
        self._notifier.start()

    def stop(self):
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        # Close live client connections so their threads exit promptly
        # instead of lingering until the recv timeout. shutdown() first:
        # a bare close() only drops the fd while a client thread may still
        # be blocked in recv() on the duplicated descriptor.
        with self._clients_lock:
            conns = [conn for conn, _state in self._clients.values()]
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Main accept loop
    # ------------------------------------------------------------------

    def _run(self):
        raw_sock = self._server_sock

        if self.certfile and self.keyfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
        else:
            ctx = None

        logger.info(f"EPS listening on {self.host}:{self.port}"
                    f" ({'TLS' if ctx else 'plaintext'})")

        while not self._stop_event.is_set():
            try:
                conn, addr = raw_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            peer = f"{addr[0]}:{addr[1]}"
            logger.info(f"Client connected: {peer}")
            if self.on_client_connected:
                self.on_client_connected(peer)

            t = threading.Thread(target=self._handle_client,
                                 args=(conn, peer, ctx),
                                 daemon=True, name=f"eps-client-{peer}")
            with self._clients_lock:
                self._clients[t] = (conn, ClientState())
            t.start()

        raw_sock.close()
        logger.info("EPS server stopped.")

    # ------------------------------------------------------------------
    # Per-client handler
    # ------------------------------------------------------------------

    def _handle_client(self, conn: socket.socket, peer: str,
                       tls_ctx: Optional[ssl.SSLContext] = None):
        # TLS handshake happens here, in the per-client thread, so a client
        # that connects and then goes silent cannot stall the accept loop
        # (and with it every other client's handshake).
        if tls_ctx is not None:
            try:
                conn.settimeout(10.0)
                conn = tls_ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                logger.warning(f"TLS handshake failed from {peer}: {e}")
                conn.close()
                self._remove_client(peer)
                return

        buf = b""
        # Find this connection's write lock (set up in _run before launching us).
        with self._clients_lock:
            entry = self._clients.get(threading.current_thread())
        write_lock = entry[1].write_lock if entry else threading.Lock()
        try:
            conn.settimeout(60.0)
            while not self._stop_event.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk

                # Electrum protocol: newline-delimited JSON
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        request = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning(f"{peer}: malformed JSON")
                        continue
                    response = self._dispatch(request, peer)
                    if response is not None:
                        payload = json.dumps(response).encode() + b"\n"
                        try:
                            with write_lock:
                                conn.sendall(payload)
                        except OSError:
                            break

        except Exception as e:
            logger.exception(f"{peer}: unhandled error: {e}")
        finally:
            conn.close()
            self._remove_client(peer)

    def _remove_client(self, peer: str):
        t = threading.current_thread()
        with self._clients_lock:
            removed = self._clients.pop(t, None)
        if removed is not None:
            logger.info(f"Client disconnected: {peer}")
            if self.on_client_disconnected:
                self.on_client_disconnected(peer)

    # ------------------------------------------------------------------
    # Method dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, request, peer: str) -> Optional[dict]:
        # Validate the envelope before touching it: a JSON array/scalar line
        # must get an Invalid Request reply, not kill the connection.
        if not isinstance(request, dict):
            logger.warning(f"{peer}: non-object request, ignoring")
            return self._error(None, -32600, "Invalid Request: expected a JSON object")
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", [])
        if not isinstance(method, str) or not isinstance(params, list):
            return self._error(req_id, -32600,
                               "Invalid Request: 'method' must be a string, 'params' a list")

        handler = self._methods.get(method)
        if handler is None:
            return self._error(req_id, -32601, f"Unknown method: {method}")

        try:
            result = handler(self, params, peer)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except ElectrumServerError as e:
            # Expected protocol-level failures (e.g. merkle proof requested
            # for a tx that a reorg moved out of the block). Use code 1 like
            # ElectrumX; -32603 would look like a server malfunction to the
            # client and is treated as disconnect-worthy in some contexts.
            logger.warning(f"{peer} -> {method}: {e}")
            return self._error(req_id, 1, str(e))
        except (ValueError, IndexError, TypeError, AttributeError) as e:
            # Bad client input (missing/mistyped params, invalid hex): tell
            # the client its request was wrong instead of logging a traceback
            # and claiming an internal error.
            logger.debug(f"{peer} -> {method}: invalid params: {e}")
            return self._error(req_id, -32602, f"Invalid params: {e}")
        except RPCError as e:
            logger.warning(f"{peer} -> {method}: RPC error: {e}")
            return self._error(req_id, e.code, e.message)
        except Exception as e:
            logger.exception(f"{peer} -> {method}: internal error: {e}")
            return self._error(req_id, -32603, str(e))

    @staticmethod
    def _error(req_id, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    # ------------------------------------------------------------------
    # Protocol method implementations
    # ------------------------------------------------------------------

    def _method_server_version(self, params, peer):
        client_ver = params[0] if params else "unknown"
        client_proto = params[1] if len(params) > 1 else PROTOCOL_VERSION_MIN
        agreed = _negotiate_protocol(client_proto)
        state = self._client_state()
        if state:
            state.protocol_version = agreed
        logger.info(f"{peer}: server.version client={client_ver} proto={agreed}")
        return [SERVER_VERSION, agreed]

    def _method_server_banner(self, params, peer):
        info = self.rpc.getblockchaininfo()
        blocks = info.get("blocks", "?")
        chain = info.get("chain", "?")
        return (f"Electrum Personal Server (plugin)\n"
                f"Bitcoin Core: chain={chain}, height={blocks}")

    def _method_server_features(self, params, peer):
        """
        Electrum's interface validates this response right after server.version
        and disconnects unless `genesis_hash` matches the network it expects.
        See electrum/interface.py — Interface.open_session().
        """
        try:
            genesis_hash = self.rpc.getblockhash(0)
        except Exception as e:
            logger.warning(f"server.features: could not fetch genesis hash: {e}")
            genesis_hash = ""
        try:
            tip = self.rpc.getblockcount()
        except Exception:
            tip = 0
        try:
            chain_info = self.rpc.getblockchaininfo()
            pruning = chain_info.get("pruneheight") if chain_info.get("pruned") else None
        except Exception:
            pruning = None
        return {
            "genesis_hash": genesis_hash,
            "hash_function": "sha256",
            "server_version": SERVER_VERSION,
            "protocol_min": PROTOCOL_VERSION_MIN,
            "protocol_max": PROTOCOL_VERSION_MAX,
            "pruning": pruning,
            "hosts": {},
        }

    def _method_server_ping(self, params, peer):
        pong_len = int(params[0]) if params else 0
        return {"data": "0" * pong_len}

    def _method_server_peers_subscribe(self, params, peer):
        return []   # we are a single-server setup; no peers

    def _method_server_donation_address(self, params, peer):
        return ""

    def _method_blockchain_headers_subscribe(self, params, peer):
        t = threading.current_thread()
        with self._clients_lock:
            entry = self._clients.get(t)
            if entry:
                entry[1].headers_sub = True
        return self._current_header()

    def _method_blockchain_scriptpubkey_subscribe(self, params, peer):
        if not params:
            raise ElectrumServerError("scriptPubKey required")
        spk_hex = params[0].lower().strip()
        self._script_watcher.ensure_watched(spk_hex)
        t = threading.current_thread()
        with self._clients_lock:
            entry = self._clients.get(t)
            if entry:
                entry[1].scriptpubkey_subs.add(spk_hex)
        return self._spk_status(spk_hex)

    def _method_blockchain_scriptpubkey_get_history(self, params, peer):
        spk_hex = params[0].lower().strip()
        self._script_watcher.ensure_watched(spk_hex)
        # Finalized protocol 1.7 wraps the list in a dict (electrum-protocol PR #17).
        return {"history": self._get_history(spk_hex=spk_hex)}

    def _method_blockchain_scriptpubkey_get_balance(self, params, peer):
        spk_hex = params[0].lower().strip()
        self._script_watcher.ensure_watched(spk_hex)
        return self._get_balance(spk_hex=spk_hex)

    def _method_blockchain_scriptpubkey_listunspent(self, params, peer):
        spk_hex = params[0].lower().strip()
        self._script_watcher.ensure_watched(spk_hex)
        # Finalized protocol 1.7 wraps the list in a dict (electrum-protocol PR #17).
        return {"utxos": self._listunspent(spk_hex=spk_hex)}

    def _method_blockchain_outpoint_subscribe(self, params, peer):
        if len(params) < 2:
            raise ElectrumServerError("txid and vout required")
        txid = params[0]
        vout = int(params[1])
        # Finalized 1.7: client always sends the outpoint's scriptPubKey as a
        # third param. Import it so Core tracks the output even if we've never
        # seen its address before (needed for gettxout on foreign outpoints).
        if len(params) > 2 and params[2]:
            try:
                self._script_watcher.ensure_watched(str(params[2]).lower().strip())
            except Exception as e:
                logger.debug(f"outpoint.subscribe: spk_hint import failed: {e}")
        t = threading.current_thread()
        with self._clients_lock:
            entry = self._clients.get(t)
            if entry:
                entry[1].outpoint_subs.add((txid, vout))
        return self._outpoint_status(txid, vout)

    def _method_blockchain_transaction_get(self, params, peer):
        txid = params[0]
        verbose = bool(params[1]) if len(params) > 1 else False
        return self._get_transaction(txid, verbose)

    def _get_transaction(self, txid: str, verbose: bool):
        """
        Fetch a transaction without requiring -txindex.

        Electrum only asks for txids it saw in a history we served, and every
        one of those is a wallet tx, so the wallet RPC gettransaction is tried
        first: it serves confirmed txs on default and pruned nodes alike.
        getrawtransaction is the fallback for mempool txs that don't involve
        the wallet (and anything else on a txindex node).
        """
        try:
            tx = self.rpc.call("gettransaction", txid, True, verbose)
        except RPCError:
            return self.rpc.getrawtransaction(txid, verbose)
        if not verbose:
            return tx["hex"]
        # Approximate getrawtransaction's verbose shape from what the wallet has.
        decoded = dict(tx.get("decoded") or {})
        decoded.setdefault("hex", tx.get("hex"))
        for key in ("blockhash", "blockheight", "blocktime", "confirmations", "time"):
            if key in tx:
                decoded.setdefault(key, tx[key])
        return decoded

    def _method_blockchain_transaction_get_merkle(self, params, peer):
        txid = params[0]
        height = params[1]
        blockhash = self.rpc.getblockhash(height)
        block = self.rpc.getblock(blockhash, 1)
        txids = block.get("tx", [])
        try:
            pos = txids.index(txid)
        except ValueError:
            raise ElectrumServerError(f"tx {txid} not in block at height {height}")
        branch = _merkle_branch(txids, pos)
        return {"block_height": height, "pos": pos, "merkle": branch}

    def _method_blockchain_transaction_broadcast(self, params, peer):
        rawhex = params[0]
        txid = self.rpc.sendrawtransaction(rawhex)
        return txid

    def _raw_header(self, height: int) -> str:
        """80-byte block header as hex. getblockheader(verbose=False) returns
        exactly that and, unlike getblock, still works for heights a pruned
        node has discarded."""
        return self.rpc.getblockheader(self.rpc.getblockhash(height), False)

    def _method_blockchain_block_header(self, params, peer):
        height = int(params[0])
        return self._raw_header(height)

    def _method_blockchain_block_headers(self, params, peer):
        start = int(params[0])
        count = int(params[1])
        try:
            tip = self.rpc.getblockcount()
        except RPCError:
            tip = start

        end = min(start + count - 1, tip)
        headers_list: List[str] = []
        for h in range(start, end + 1):
            try:
                headers_list.append(self._raw_header(h))
            except RPCError:
                break

        n = len(headers_list)
        return {"headers": headers_list, "count": n, "max": BLOCK_HEADERS_MAX}

    def _method_blockchain_estimatefee(self, params, peer):
        blocks = int(params[0]) if params else 6
        result = self.rpc.estimatesmartfee(blocks)
        feerate = result.get("feerate")
        if feerate is None:
            return -1
        # Electrum wants BTC/kB
        return feerate

    def _method_mempool_get_info(self, params, peer):
        # Protocol >= 1.6 replacement for the old blockchain.relayfee.
        try:
            info = self.rpc.call("getmempoolinfo")
            return {
                "minrelaytxfee": info.get("mempoolminfee", 0.00001),
                "size": info.get("size", 0),
            }
        except Exception:
            return {"minrelaytxfee": 0.00001, "size": 0}

    def _method_blockchain_transaction_id_from_pos(self, params, peer):
        height = int(params[0])
        tx_pos = int(params[1])
        merkle = bool(params[2]) if len(params) > 2 else False
        blockhash = self.rpc.getblockhash(height)
        block = self.rpc.getblock(blockhash, 1)
        txids = block.get("tx", [])
        if tx_pos >= len(txids):
            raise ElectrumServerError(f"tx_pos {tx_pos} out of range")
        tx_hash = txids[tx_pos]
        if not merkle:
            return tx_hash
        return {"tx_hash": tx_hash, "merkle": _merkle_branch(txids, tx_pos)}

    def _method_mempool_get_fee_histogram(self, params, peer):
        # Approximate: Bitcoin Core doesn't expose a fee histogram directly.
        # Return empty for now; clients degrade gracefully.
        return []

    # ------------------------------------------------------------------
    # Method registry
    # ------------------------------------------------------------------

    _methods = {
        "server.version":                       _method_server_version,
        "server.banner":                        _method_server_banner,
        "server.features":                      _method_server_features,
        "server.ping":                          _method_server_ping,
        "server.peers.subscribe":               _method_server_peers_subscribe,
        "server.donation_address":              _method_server_donation_address,
        "blockchain.headers.subscribe":         _method_blockchain_headers_subscribe,
        "blockchain.scriptpubkey.subscribe":    _method_blockchain_scriptpubkey_subscribe,
        "blockchain.scriptpubkey.get_history":  _method_blockchain_scriptpubkey_get_history,
        "blockchain.scriptpubkey.get_balance":  _method_blockchain_scriptpubkey_get_balance,
        "blockchain.scriptpubkey.listunspent":  _method_blockchain_scriptpubkey_listunspent,
        "blockchain.outpoint.subscribe":        _method_blockchain_outpoint_subscribe,
        "blockchain.transaction.get":           _method_blockchain_transaction_get,
        "blockchain.transaction.get_merkle":    _method_blockchain_transaction_get_merkle,
        "blockchain.transaction.broadcast":     _method_blockchain_transaction_broadcast,
        "blockchain.transaction.id_from_pos":   _method_blockchain_transaction_id_from_pos,
        "blockchain.block.header":              _method_blockchain_block_header,
        "blockchain.block.headers":             _method_blockchain_block_headers,
        "blockchain.estimatefee":               _method_blockchain_estimatefee,
        "mempool.get_info":                     _method_mempool_get_info,
        "mempool.get_fee_histogram":            _method_mempool_get_fee_histogram,
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _client_state(self) -> Optional[ClientState]:
        with self._clients_lock:
            entry = self._clients.get(threading.current_thread())
        return entry[1] if entry else None

    def _resolve_query(self, *, spk_hex: str = None):
        """Return (address, spk_hex) for balance/history queries."""
        if spk_hex:
            spk_hex = spk_hex.lower().strip()
            address = self._script_watcher.address_for_spk(spk_hex)
            return address, spk_hex
        return None, None

    def _current_header(self) -> dict:
        try:
            height = self.rpc.getblockcount()
            bh = self.rpc.getblockhash(height)
            with self._tip_lock:
                self._tip_height = height
                self._tip_hash = bh
            return {
                "height": height,
                "hex": self.rpc.getblockheader(bh, False),
            }
        except Exception as e:
            logger.warning(f"_current_header failed: {e}")
            return {"height": 0, "hex": ""}

    def _get_history(self, *, spk_hex: str = None) -> List[dict]:
        if not spk_hex:
            return []
        return self._get_history_for_script(spk_hex.lower().strip())

    def _get_history_for_script(self, spk_hex: str) -> List[dict]:
        """
        Electrum-protocol history for a script, from the wallet tx index:
          - confirmed entries first, in ascending height order
          - mempool entries (height 0, or -1 with unconfirmed parents) last,
            each carrying a non-negative integer `fee` in sats (required)
        Ordering is deterministic so the status hash is stable between polls.
        """
        items = self._wallet_index.history_for_spk(spk_hex)
        confirmed = sorted(((txid, h) for txid, h, _fee in items if h > 0),
                           key=lambda x: (x[1], x[0]))
        history: List[dict] = [
            {"tx_hash": txid, "height": h} for txid, h in confirmed
        ]
        for txid, h, fee in sorted(items, key=lambda x: x[0]):
            if h > 0:
                continue
            if fee is None:
                # Core reported no fee; skip rather than violate the protocol.
                continue
            history.append({"tx_hash": txid, "height": h, "fee": fee})
        return history

    def _height_from_confs(self, confs: int) -> int:
        if confs is None or confs <= 0:
            return 0
        # Use cached tip from _current_header if available; otherwise query.
        tip = self._tip_height
        if tip <= 0:
            try:
                tip = self.rpc.getblockcount()
                self._tip_height = tip
            except RPCError:
                return 0
        return tip - confs + 1

    def _get_balance(self, *, spk_hex: str = None) -> dict:
        address, spk_hex = self._resolve_query(spk_hex=spk_hex)
        if address is None and spk_hex is None:
            return {"confirmed": 0, "unconfirmed": 0}

        confirmed_utxos = self._utxos_for_script(address, spk_hex, 1, 9999999)
        confirmed = sum(int(round(u["amount"] * 1e8)) for u in confirmed_utxos)

        unconfirmed_utxos = self._utxos_for_script(address, spk_hex, 0, 0)
        unconfirmed = sum(int(round(u["amount"] * 1e8)) for u in unconfirmed_utxos)

        return {"confirmed": confirmed, "unconfirmed": unconfirmed}

    def _listunspent(self, *, spk_hex: str = None) -> List[dict]:
        address, spk_hex = self._resolve_query(spk_hex=spk_hex)
        if address is None and spk_hex is None:
            return []
        result = []
        for utxo in self._utxos_for_script(address, spk_hex, 0, 9999999):
            result.append({
                "tx_hash": utxo["txid"],
                "tx_pos": utxo["vout"],
                "height": utxo.get("confirmations", 0),
                "value": int(round(utxo["amount"] * 1e8)),
            })
        return result

    def _utxos_for_script(self, address: Optional[str], spk_hex: Optional[str],
                          minconf: int, maxconf: int) -> List[dict]:
        if address:
            return self.rpc.listunspent(minconf, maxconf, [address])
        if not spk_hex:
            return []
        utxos = self.rpc.listunspent(minconf, maxconf)
        return [u for u in utxos if self._utxo_matches_spk(u, spk_hex)]

    @staticmethod
    def _utxo_matches_spk(utxo: dict, spk_hex: str) -> bool:
        # listunspent reports each output's scriptPubKey hex directly, so no
        # address conversion or (txindex-dependent) getrawtransaction needed.
        return (utxo.get("scriptPubKey") or "").lower() == spk_hex.lower()

    def _history_status(self, history: List[dict]) -> Optional[str]:
        if not history:
            return None
        history_str = "".join(
            f"{item['tx_hash']}:{item['height']}:" for item in history
        )
        return hashlib.sha256(history_str.encode()).hexdigest()

    def _spk_status(self, spk_hex: str) -> Optional[str]:
        return self._history_status(self._get_history(spk_hex=spk_hex))

    def _outpoint_status(self, txid: str, vout: int) -> dict:
        try:
            txout = self.rpc.call("gettxout", txid, vout, True)
        except RPCError:
            txout = None
        if txout:
            confs = txout.get("confirmations", 0)
            height = self._height_from_confs(confs) if confs else 0
            # Finalized 1.7 renamed this field from "height" to "funder_height".
            return {"funder_height": height}

        try:
            results = self.rpc.call(
                "gettxspendingprevout", [{"txid": txid, "vout": vout}])
        except RPCError:
            results = None
        if results and results[0]:
            spender = results[0].get("spendingtxid")
            if spender:
                try:
                    spender_tx = self.rpc.getrawtransaction(spender, True)
                    confs = spender_tx.get("confirmations", 0)
                    spender_height = self._height_from_confs(confs) if confs else 0
                except RPCError:
                    spender_height = 0
                return {"spender_txhash": spender, "spender_height": spender_height}
        return {}

    # ------------------------------------------------------------------
    # Notification loop — polls for new blocks and pushes to subscribers
    # ------------------------------------------------------------------

    def _notification_loop(self):
        """
        Poll Bitcoin Core every ~10 seconds. On new blocks, push header
        notifications and refresh script subscription statuses.
        """
        while not self._stop_event.is_set():
            try:
                height = self.rpc.getblockcount()
                with self._tip_lock:
                    new_block = height != self._tip_height
                    if new_block:
                        self._tip_height = height
                        self._push_header_notification(height)
                self._push_script_notifications()
            except Exception as e:
                logger.debug(f"Notification loop error: {e}")
            self._stop_event.wait(timeout=10)

    def _push_header_notification(self, height: int):
        try:
            header_hex = self._raw_header(height)
            notification = json.dumps({
                "jsonrpc": "2.0",
                "method": "blockchain.headers.subscribe",
                "params": [{"height": height, "hex": header_hex}],
            }).encode() + b"\n"

            with self._clients_lock:
                clients = list(self._clients.values())

            for conn, state in clients:
                if state.headers_sub:
                    try:
                        with state.write_lock:
                            conn.sendall(notification)
                    except OSError:
                        pass
        except Exception as e:
            logger.warning(f"Failed to push header notification: {e}")

    def _push_script_notifications(self):
        with self._clients_lock:
            clients = list(self._clients.values())

        # Finalized 1.7: the client matches notifications by the *scripthash*
        # of the scriptPubKey it subscribed with (interface.py converts
        # spk -> sh for the notification key), so the identifier here MUST be
        # scripthash(spk), not the spk hex itself.
        watched_spk: set = set()
        for _conn, state in clients:
            watched_spk.update(state.scriptpubkey_subs)

        for spk in watched_spk:
            status = self._history_status(self._get_history(spk_hex=spk))
            cache_key = ("spk", spk)
            if self._status_cache.get(cache_key) == status:
                continue
            self._status_cache[cache_key] = status

            notif = json.dumps({
                "jsonrpc": "2.0",
                "method": "blockchain.scriptpubkey.subscribe",
                "params": [scriptpubkey_to_scripthash(spk), status],
            }).encode() + b"\n"

            for conn, state in clients:
                if spk in state.scriptpubkey_subs:
                    try:
                        with state.write_lock:
                            conn.sendall(notif)
                    except OSError:
                        pass
