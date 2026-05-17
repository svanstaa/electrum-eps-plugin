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
from typing import Dict, List, Optional, Callable, Any

from .rpc import BitcoinRPC, RPCError
from .addresses import address_to_scripthash

logger = logging.getLogger("eps.server")

PROTOCOL_VERSION = "1.4"
SERVER_VERSION = "EPS-plugin/0.1.0"


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
# Subscription state per-client
# ---------------------------------------------------------------------------

class ClientState:
    def __init__(self):
        self.scripthash_subs: set = set()   # scripthashes this client subscribed to
        self.headers_sub: bool = False
        # Protects concurrent writes from the per-client handler thread and the
        # notification thread (both can call conn.sendall on the same socket).
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

        # Per-instance scripthash → address cache (populated by register_address)
        self._scripthash_cache: Dict[str, str] = {}

        # Notification callbacks set by qt.py (so the GUI can update status)
        self.on_client_connected: Optional[Callable[[str], None]] = None
        self.on_client_disconnected: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
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
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Main accept loop
    # ------------------------------------------------------------------

    def _run(self):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(5)
        raw_sock.settimeout(1.0)   # so we can check _stop_event
        self._server_sock = raw_sock

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

            if ctx:
                try:
                    conn = ctx.wrap_socket(conn, server_side=True)
                except ssl.SSLError as e:
                    logger.warning(f"TLS handshake failed from {addr}: {e}")
                    conn.close()
                    continue

            peer = f"{addr[0]}:{addr[1]}"
            logger.info(f"Client connected: {peer}")
            if self.on_client_connected:
                self.on_client_connected(peer)

            t = threading.Thread(target=self._handle_client,
                                 args=(conn, peer),
                                 daemon=True, name=f"eps-client-{peer}")
            with self._clients_lock:
                self._clients[t] = (conn, ClientState())
            t.start()

        raw_sock.close()
        logger.info("EPS server stopped.")

    # ------------------------------------------------------------------
    # Per-client handler
    # ------------------------------------------------------------------

    def _handle_client(self, conn: socket.socket, peer: str):
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
            t = threading.current_thread()
            with self._clients_lock:
                self._clients.pop(t, None)
            logger.info(f"Client disconnected: {peer}")
            if self.on_client_disconnected:
                self.on_client_disconnected(peer)

    # ------------------------------------------------------------------
    # Method dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, request: dict, peer: str) -> Optional[dict]:
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", [])

        handler = self._methods.get(method)
        if handler is None:
            return self._error(req_id, -32601, f"Unknown method: {method}")

        try:
            result = handler(self, params, peer)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
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
        protocol_ver = params[1] if len(params) > 1 else PROTOCOL_VERSION
        logger.info(f"{peer}: server.version client={client_ver} proto={protocol_ver}")
        return [SERVER_VERSION, PROTOCOL_VERSION]

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
            "protocol_min": PROTOCOL_VERSION,
            "protocol_max": PROTOCOL_VERSION,
            "pruning": pruning,
            "hosts": {},   # we don't advertise alt connection methods
        }

    def _method_server_ping(self, params, peer):
        return None

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

    def _method_blockchain_scripthash_subscribe(self, params, peer):
        if not params:
            raise ElectrumServerError("scripthash required")
        scripthash = params[0]
        t = threading.current_thread()
        with self._clients_lock:
            entry = self._clients.get(t)
            if entry:
                entry[1].scripthash_subs.add(scripthash)
        return self._scripthash_status(scripthash)

    def _method_blockchain_scripthash_get_history(self, params, peer):
        scripthash = params[0]
        return self._get_history(scripthash)

    def _method_blockchain_scripthash_get_balance(self, params, peer):
        scripthash = params[0]
        address = self._scripthash_to_address(scripthash)
        if address is None:
            return {"confirmed": 0, "unconfirmed": 0}

        # confirmed: minconf=1, maxconf=9999999
        confirmed_utxos = self.rpc.listunspent(1, 9999999, [address])
        confirmed = sum(int(round(u["amount"] * 1e8)) for u in confirmed_utxos)

        # unconfirmed: minconf=0, maxconf=0
        unconfirmed_utxos = self.rpc.listunspent(0, 0, [address])
        unconfirmed = sum(int(round(u["amount"] * 1e8)) for u in unconfirmed_utxos)

        return {"confirmed": confirmed, "unconfirmed": unconfirmed}

    def _method_blockchain_scripthash_listunspent(self, params, peer):
        scripthash = params[0]
        address = self._scripthash_to_address(scripthash)
        if address is None:
            return []
        unspent = self.rpc.listunspent(0, 9999999, [address])
        result = []
        for utxo in unspent:
            result.append({
                "tx_hash": utxo["txid"],
                "tx_pos": utxo["vout"],
                "height": utxo.get("confirmations", 0),  # Core gives confirms, not height
                "value": int(round(utxo["amount"] * 1e8)),
            })
        return result

    def _method_blockchain_transaction_get(self, params, peer):
        txid = params[0]
        verbose = params[1] if len(params) > 1 else False
        return self.rpc.getrawtransaction(txid, verbose)

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

    def _method_blockchain_block_header(self, params, peer):
        height = int(params[0])
        blockhash = self.rpc.getblockhash(height)
        # Return raw hex header (80 bytes)
        block = self.rpc.getblock(blockhash, 0)  # verbosity=0 → raw hex
        # Raw block starts with the 80-byte header
        return block[:160]  # first 80 bytes = 160 hex chars

    def _method_blockchain_block_headers(self, params, peer):
        start = int(params[0])
        count = int(params[1])
        headers_hex = ""
        for h in range(start, start + count):
            try:
                bh = self.rpc.getblockhash(h)
                raw = self.rpc.getblock(bh, 0)
                headers_hex += raw[:160]
            except RPCError:
                break
        return {"hex": headers_hex, "count": len(headers_hex) // 160}

    def _method_blockchain_estimatefee(self, params, peer):
        blocks = int(params[0]) if params else 6
        result = self.rpc.estimatesmartfee(blocks)
        feerate = result.get("feerate")
        if feerate is None:
            return -1
        # Electrum wants BTC/kB
        return feerate

    def _method_blockchain_relayfee(self, params, peer):
        # Electrum protocol <= 1.5 polls this at startup. If we don't
        # implement it, the server returns METHOD_NOT_FOUND (-32601) which
        # Electrum's interface treats as GracefulDisconnect — causing the
        # status to oscillate between "connecting" and "not connected".
        try:
            info = self.rpc.call("getmempoolinfo")
            # Core returns BTC/kvB; the Electrum protocol expects BTC/kB too.
            return info.get("mempoolminfee", 0.00001)
        except Exception:
            return 0.00001  # 1000 sat/kB fallback

    def _method_mempool_get_info(self, params, peer):
        # Protocol >= 1.6 uses this instead of blockchain.relayfee.
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
        "blockchain.scripthash.subscribe":      _method_blockchain_scripthash_subscribe,
        "blockchain.scripthash.get_history":    _method_blockchain_scripthash_get_history,
        "blockchain.scripthash.get_balance":    _method_blockchain_scripthash_get_balance,
        "blockchain.scripthash.listunspent":    _method_blockchain_scripthash_listunspent,
        "blockchain.transaction.get":           _method_blockchain_transaction_get,
        "blockchain.transaction.get_merkle":    _method_blockchain_transaction_get_merkle,
        "blockchain.transaction.broadcast":     _method_blockchain_transaction_broadcast,
        "blockchain.transaction.id_from_pos":   _method_blockchain_transaction_id_from_pos,
        "blockchain.block.header":              _method_blockchain_block_header,
        "blockchain.block.headers":             _method_blockchain_block_headers,
        "blockchain.estimatefee":               _method_blockchain_estimatefee,
        "blockchain.relayfee":                  _method_blockchain_relayfee,
        "mempool.get_info":                     _method_mempool_get_info,
        "mempool.get_fee_histogram":            _method_mempool_get_fee_histogram,
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _current_header(self) -> dict:
        try:
            height = self.rpc.getblockcount()
            bh = self.rpc.getblockhash(height)
            header_info = self.rpc.getblockheader(bh, True)
            with self._tip_lock:
                self._tip_height = height
                self._tip_hash = bh
            return {
                "height": height,
                "hex": self.rpc.getblock(bh, 0)[:160],
            }
        except Exception as e:
            logger.warning(f"_current_header failed: {e}")
            return {"height": 0, "hex": ""}

    def _get_history(self, scripthash: str) -> List[dict]:
        """
        Return tx history for a `scripthash`, combining several Bitcoin Core
        RPCs because no single one is sufficient for a watch-only descriptor
        wallet:

          1. listunspent (per-address) — gives us txids of unspent receives.
          2. listsinceblock — confirmed wallet activity (sends and receives).
          3. getrawmempool walk — catches mempool sends that
             listtransactions/listsinceblock miss for watch-only descriptor
             wallets when both inputs and outputs are within watched ranges.

        NOTE: This is O(mempool size) per query. Fine for a personal server
        on testnet; for mainnet under load we should maintain an incremental
        per-address tx index updated on each new block / mempool poll.
        """
        address = self._scripthash_to_address(scripthash)
        if address is None:
            logger.debug(f"No address known for scripthash {scripthash}")
            return []

        seen: Dict[str, int] = {}  # txid -> height (0 = mempool)

        # 1. UTXOs currently sitting at this address.
        try:
            for u in self.rpc.listunspent(0, 9999999, [address]):
                seen.setdefault(u["txid"],
                                self._height_from_confs(u.get("confirmations", 0)))
        except RPCError as e:
            logger.debug(f"listunspent for {address} failed: {e}")

        # 2. Confirmed wallet activity since genesis.
        # listsinceblock("", 1, include_watchonly=True, include_removed=True)
        try:
            result = self.rpc.call(
                "listsinceblock", "", 1, True, True)
            for tx in (result.get("transactions", [])
                       + result.get("removed", [])):
                if tx.get("address") == address:
                    seen.setdefault(
                        tx["txid"],
                        self._height_from_confs(tx.get("confirmations", 0)))
        except RPCError as e:
            logger.debug(f"listsinceblock failed: {e}")

        # 3. Mempool walk: covers watch-only "internal" sends that
        # listtransactions/listsinceblock leave out of their details.
        try:
            mempool = self.rpc.call("getrawmempool")
        except RPCError:
            mempool = []
        for txid in mempool:
            if txid in seen:
                continue
            if self._tx_touches_address(txid, address):
                seen[txid] = 0

        # Electrum protocol requires:
        #   - confirmed entries first, in ascending height order
        #   - mempool entries (height <= 0) last
        #   - mempool entries MUST contain a non-negative integer `fee` in sats
        confirmed = sorted(
            [(txid, h) for txid, h in seen.items() if h > 0],
            key=lambda x: x[1],
        )
        mempool_items = [(txid, h) for txid, h in seen.items() if h <= 0]

        history: List[dict] = [
            {"tx_hash": txid, "height": h} for txid, h in confirmed
        ]
        for txid, _h in mempool_items:
            fee_sats = self._mempool_fee_sats(txid)
            if fee_sats is None:
                # No fee available (race: tx left mempool between getrawmempool
                # and the fee lookup). Skip rather than violate the protocol.
                continue
            history.append({
                "tx_hash": txid,
                "height": self._mempool_height(txid),
                "fee": fee_sats,
            })
        return history

    def _mempool_fee_sats(self, txid: str) -> Optional[int]:
        """Return the fee (sats) for a mempool tx, or None if not in mempool
        any more or the lookup fails."""
        try:
            entry = self.rpc.call("getmempoolentry", txid)
        except RPCError:
            return None
        # Core returns fees in BTC under either 'fees.base' (modern) or 'fee'
        # (very old releases).
        fees = entry.get("fees") or {}
        fee_btc = fees.get("base", entry.get("fee"))
        if fee_btc is None:
            return None
        return int(round(fee_btc * 1e8))

    def _mempool_height(self, txid: str) -> int:
        """0 if all inputs are confirmed; -1 if any input is still in mempool."""
        try:
            entry = self.rpc.call("getmempoolentry", txid)
        except RPCError:
            return 0
        return -1 if entry.get("ancestorcount", 1) > 1 else 0

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

    def _tx_touches_address(self, txid: str, address: str) -> bool:
        """True if `address` appears in any output or in any spent prevout
        of `txid`. Used for the mempool fallback in _get_history."""
        try:
            tx = self.rpc.getrawtransaction(txid, True)
        except RPCError:
            return False
        for vout in tx.get("vout", []):
            if self._vout_address(vout) == address:
                return True
        for vin in tx.get("vin", []):
            prev_txid = vin.get("txid")
            prev_n = vin.get("vout")
            if prev_txid is None or prev_n is None:
                continue
            try:
                prev = self.rpc.getrawtransaction(prev_txid, True)
            except RPCError:
                continue
            try:
                prev_out = prev["vout"][prev_n]
            except (KeyError, IndexError):
                continue
            if self._vout_address(prev_out) == address:
                return True
        return False

    @staticmethod
    def _vout_address(vout: dict) -> Optional[str]:
        spk = vout.get("scriptPubKey", {})
        addr = spk.get("address")
        if addr:
            return addr
        addrs = spk.get("addresses") or []
        return addrs[0] if addrs else None

    def _scripthash_status(self, scripthash: str) -> Optional[str]:
        """
        Compute the Electrum 'status' string for a scripthash:
        SHA256 of the history string, or None if history is empty.
        """
        history = self._get_history(scripthash)
        if not history:
            return None
        history_str = "".join(
            f"{item['tx_hash']}:{item['height']}:" for item in history
        )
        return hashlib.sha256(history_str.encode()).hexdigest()

    def _scripthash_to_address(self, scripthash: str) -> Optional[str]:
        """
        Reverse-lookup: find a Bitcoin address that hashes to this scripthash.
        Cache is populated via register_address() after wallet import.
        """
        return self._scripthash_cache.get(scripthash)

    def register_address(self, address: str):
        """Register an address so we can look it up by scripthash."""
        sh = address_to_scripthash(address)
        self._scripthash_cache[sh] = address

    # ------------------------------------------------------------------
    # Notification loop — polls for new blocks and pushes to subscribers
    # ------------------------------------------------------------------

    def _notification_loop(self):
        """
        Poll Bitcoin Core every ~10 seconds. If a new block arrived,
        send blockchain.headers.subscribe notifications to subscribed clients.
        """
        while not self._stop_event.is_set():
            try:
                height = self.rpc.getblockcount()
                with self._tip_lock:
                    if height != self._tip_height:
                        self._tip_height = height
                        self._push_header_notification(height)
            except Exception as e:
                logger.debug(f"Notification loop error: {e}")
            self._stop_event.wait(timeout=10)

    def _push_header_notification(self, height: int):
        try:
            bh = self.rpc.getblockhash(height)
            raw = self.rpc.getblock(bh, 0)
            header_hex = raw[:160]
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
