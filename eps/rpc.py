# eps_plugin/rpc.py
#
# Thin, synchronous wrapper around Bitcoin Core's JSON-RPC interface.
# Intentionally has no Electrum imports so it can be unit-tested standalone.

import json
import base64
import logging
import os
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

logger = logging.getLogger("eps.rpc")


def read_cookie_auth(datadir: str, subdir: str = "") -> tuple:
    """Read Bitcoin Core's .cookie file → (user, password).

    `subdir` is the per-network directory under `datadir` ('' for mainnet,
    e.g. 'testnet3' / 'testnet4' / 'signet' / 'regtest' otherwise).

    Returns ('', '') if `datadir` is empty or the cookie file cannot be read
    (Core not running, wrong path, no read permission, or static
    rpcuser/rpcpassword configured so Core writes no cookie).
    """
    if not datadir:
        return "", ""
    cookie_path = os.path.join(
        os.path.expanduser(datadir), subdir, ".cookie")
    try:
        with open(cookie_path, "r") as f:
            content = f.read().strip()
    except OSError as e:
        logger.warning(f"Could not read Bitcoin Core cookie at {cookie_path}: {e}")
        return "", ""
    user, _, password = content.partition(":")
    return user, password


class RPCError(Exception):
    """Raised when Bitcoin Core returns a JSON-RPC error."""
    def __init__(self, code: int, message: str):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message


class BitcoinRPC:
    """
    Synchronous JSON-RPC client for Bitcoin Core.

    Instantiate once; call() is thread-safe as long as you don't mutate
    the object after construction.
    """

    def __init__(self, host: str, port: int, user: str, password: str,
                 wallet: str = ""):
        host = (host or "").strip()
        # Bracket IPv6 literals (urlparse().hostname strips them).
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        self._url = f"http://{host}:{port}"
        if wallet:
            # Wallet names may contain spaces, slashes, unicode — encode.
            self._url += f"/wallet/{urllib.parse.quote(wallet, safe='')}"
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {creds}",
        }
        self._id = 0

    # ------------------------------------------------------------------
    # Core call machinery
    # ------------------------------------------------------------------

    def call(self, method: str, *params, timeout: float = 30) -> Any:
        """
        Make a single RPC call and return the 'result' field.
        Raises RPCError on a JSON-RPC error, or urllib.error.URLError
        on a network failure.

        `timeout=None` blocks until Core answers (needed for long-running
        calls such as rescanblockchain).

        Thread-safety note: concurrent calls are safe (each is an independent
        HTTP request), but the incrementing request id is not synchronized —
        harmless, since Core does not require unique ids and we never read
        the response id.
        """
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": list(params),
        }).encode()

        req = urllib.request.Request(self._url, data=payload,
                                     headers=self._headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # Core answers some failures without a JSON-RPC body:
            #   401/403 auth failures  — empty body
            #   503 work queue full    — plain text
            #   404 unknown wallet     — plain text
            # Report those clearly instead of surfacing a JSONDecodeError.
            raw = e.read()
            ctype = (e.headers.get("Content-Type") or "").lower()
            if "json" not in ctype:
                detail = raw.decode(errors="replace").strip()[:200]
                if e.code in (401, 403):
                    raise RPCError(e.code, "RPC authentication failed "
                                           "(check rpcuser/rpcpassword or cookie)")
                if e.code == 404:
                    raise RPCError(e.code, f"wallet endpoint not found "
                                           f"(is the wallet loaded?){': ' + detail if detail else ''}")
                raise RPCError(e.code, f"HTTP {e.code} from Bitcoin Core"
                                       f"{': ' + detail if detail else ''}")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                raise RPCError(e.code, f"HTTP {e.code} from Bitcoin Core "
                                       f"(unparseable response)")

        if body.get("error"):
            err = body["error"]
            raise RPCError(err.get("code", -1), err.get("message", "unknown"))
        return body["result"]

    # ------------------------------------------------------------------
    # Convenience wrappers — only the methods EPS needs
    # ------------------------------------------------------------------

    def getblockchaininfo(self) -> dict:
        return self.call("getblockchaininfo")

    def getnetworkinfo(self) -> dict:
        return self.call("getnetworkinfo")

    def getblockcount(self) -> int:
        return self.call("getblockcount")

    def getblockhash(self, height: int) -> str:
        return self.call("getblockhash", height)

    def getblockheader(self, blockhash: str, verbose: bool = True) -> Any:
        return self.call("getblockheader", blockhash, verbose)

    def getblock(self, blockhash: str, verbosity: int = 1) -> Any:
        return self.call("getblock", blockhash, verbosity)

    def getrawtransaction(self, txid: str, verbose: bool = False) -> Any:
        return self.call("getrawtransaction", txid, verbose)

    def sendrawtransaction(self, rawhex: str) -> str:
        return self.call("sendrawtransaction", rawhex)

    def estimatesmartfee(self, conf_target: int, mode: str = "CONSERVATIVE") -> dict:
        return self.call("estimatesmartfee", conf_target, mode)

    # Wallet / address methods

    def getwalletinfo(self) -> dict:
        return self.call("getwalletinfo")

    def importdescriptors(self, requests: list) -> list:
        """
        Bitcoin Core >=0.21.  Each element of requests is a dict with
        keys: desc, timestamp, range, watchonly, label.
        """
        return self.call("importdescriptors", requests)

    def importmulti(self, requests: list, options: dict = None) -> list:
        """
        Bitcoin Core 0.17–0.20 fallback for importdescriptors.
        """
        args = [requests]
        if options:
            args.append(options)
        return self.call("importmulti", *args)

    def scantxoutset(self, action: str, scanobjects: list) -> dict:
        return self.call("scantxoutset", action, scanobjects)

    def listunspent(self, minconf: int = 0, maxconf: int = 9999999,
                    addresses: list = None) -> list:
        args = [minconf, maxconf]
        if addresses is not None:
            args.append(addresses)
        return self.call("listunspent", *args)

    def getaddressinfo(self, address: str) -> dict:
        return self.call("getaddressinfo", address)

    def rescanblockchain(self, start_height: int = 0) -> dict:
        # Blocks until the rescan finishes — hours on mainnet — so no timeout.
        return self.call("rescanblockchain", start_height, timeout=None)
