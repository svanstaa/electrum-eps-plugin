# eps_plugin/addresses.py
#
# Derives addresses from an Electrum wallet's keystores and manages
# their import into Bitcoin Core via descriptors or importmulti.

import hashlib
import threading
from typing import Dict, Optional, TYPE_CHECKING

from electrum.bip32 import BIP32Node
from electrum import bitcoin

from .rpc import BitcoinRPC, RPCError

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


# Script types Electrum uses, mapped to descriptor template fragments.
# We detect which one a keystore uses from its xpub prefix.
_XPUB_TYPE_TO_SCRIPT = {
    "standard":   "pkh",     # xpub  → P2PKH
    "p2wpkh-p2sh": "sh(wpkh",  # ypub  → P2SH-P2WPKH
    "p2wpkh":     "wpkh",    # zpub  → P2WPKH (native segwit)
}

# How many addresses to bulk-import into Core per branch (receiving/change).
# With protocol 1.7, anything beyond this range is still picked up on demand
# via scriptpubkey.subscribe, so this only bounds the initial import + rescan.
IMPORT_ADDRESS_COUNT = 100


def _script_type_for_keystore(ks) -> str:
    """Infer script type from the keystore's xpub version bytes.

    Mainnet: xpub → P2PKH, ypub → P2SH-P2WPKH, zpub → P2WPKH
    Testnet: tpub → P2PKH, upub → P2SH-P2WPKH, vpub → P2WPKH
    (Capital-letter variants are multisig equivalents.)
    """
    xpub = ks.xpub
    if xpub.startswith(("zpub", "Zpub", "vpub", "Vpub")):
        return "p2wpkh"
    if xpub.startswith(("ypub", "Ypub", "upub", "Upub")):
        return "p2wpkh-p2sh"
    return "standard"


def _is_multisig_wallet(wallet) -> bool:
    """Best-effort detection of a multisig wallet.

    Bulk import only builds single-sig descriptors (wpkh/sh(wpkh)/pkh), which
    derive entirely different addresses than a multisig wsh(sortedmulti(...))
    script. Importing those would make Core watch the wrong addresses, so we
    detect multisig up front and refuse rather than fail silently.
    """
    wallet_type = getattr(wallet, "wallet_type", "") or ""
    if "of" in wallet_type:  # e.g. "2of2", "2of3"
        return True
    try:
        return len(wallet.get_keystores()) > 1
    except Exception:
        return False


def _to_canonical_xpub(xpub: str) -> str:
    """
    Bitcoin Core only accepts canonical BIP32 keys in descriptors
    (`xpub`/`tpub`), not SLIP-132 variants (`ypub`/`zpub`/`upub`/`vpub`).
    Re-encode the xpub with the standard header bytes; the script type
    is conveyed by the descriptor wrapper (wpkh / sh(wpkh) / pkh).
    """
    node = BIP32Node.from_xkey(xpub, allow_custom_headers=True)
    if node.xtype == "standard":
        return xpub
    return node._replace(xtype="standard").to_xpub()


def normalize_script_hex(value: str, *, field: str = "scriptpubkey") -> str:
    """Validate and normalize a hex string received from an (untrusted) client.

    Returns the lower-cased hex. Raises ValueError on anything that is not
    non-empty, even-length hexadecimal, so callers don't pass garbage straight
    into ``bytes.fromhex`` (which would surface as an opaque internal error).
    """
    if not isinstance(value, str):
        raise ValueError(f"invalid {field}: expected a hex string")
    h = value.strip().lower()
    if not h or len(h) % 2 != 0:
        raise ValueError(f"invalid {field}: expected non-empty even-length hex")
    try:
        bytes.fromhex(h)
    except ValueError:
        raise ValueError(f"invalid {field}: not hexadecimal")
    return h


def scriptpubkey_to_scripthash(script: bytes) -> str:
    """Electrum scripthash from raw scriptPubKey bytes (reverse SHA256)."""
    if isinstance(script, str):
        script = bytes.fromhex(script)
    digest = hashlib.sha256(script).digest()
    return digest[::-1].hex()


def address_to_scripthash(address: str) -> str:
    """
    Convert a Bitcoin address to the reversed SHA256 scripthash format
    used by the Electrum protocol.
    """
    script = bitcoin.address_to_script(address)
    if isinstance(script, str):
        script = bytes.fromhex(script)
    return scriptpubkey_to_scripthash(script)


def _descriptor_checksum(desc: str) -> str:
    INPUT_CHARSET = (
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
    )
    CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def _poly_mod(c, val):
        c0 = c >> 35
        c = ((c & 0x7FFFFFFFF) << 5) ^ val
        if c0 & 1:
            c ^= 0xF5DEE51989
        if c0 & 2:
            c ^= 0xA9FDCA3312
        if c0 & 4:
            c ^= 0x1BAB10E32D
        if c0 & 8:
            c ^= 0x3706B1677A
        if c0 & 16:
            c ^= 0x644D626FFD
        return c

    c = 1
    cls = 0
    cls_count = 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos < 0:
            return desc
        c = _poly_mod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        cls_count += 1
        if cls_count == 3:
            c = _poly_mod(c, cls)
            cls = 0
            cls_count = 0
    if cls_count:
        c = _poly_mod(c, cls)
    for _ in range(8):
        c = _poly_mod(c, 0)
    c ^= 1

    checksum = ""
    for i in range(8):
        checksum = CHECKSUM_CHARSET[(c >> (5 * i)) & 31] + checksum
    return f"{desc}#{checksum}"


def add_descriptor_checksum(desc: str) -> str:
    """Append Bitcoin Core descriptor checksum (#...) to `desc`."""
    return _descriptor_checksum(desc)


class ScriptWatcher:
    """
    Track output scripts in Bitcoin Core. Used for Electrum protocol 1.7
    on-demand `blockchain.scriptpubkey.*` subscriptions.
    """

    def __init__(self, rpc: BitcoinRPC):
        self.rpc = rpc
        self._lock = threading.Lock()
        self._imported_spks: set = set()
        self._spk_to_address: Dict[str, Optional[str]] = {}
        self._sh_to_spk: Dict[str, str] = {}

    def register_address(self, address: str) -> None:
        script = bitcoin.address_to_script(address)
        if isinstance(script, str):
            script = bytes.fromhex(script)
        spk_hex = script.hex()
        sh = scriptpubkey_to_scripthash(script)
        with self._lock:
            self._spk_to_address[spk_hex] = address
            self._sh_to_spk[sh] = spk_hex

    def address_for_spk(self, spk_hex: str) -> Optional[str]:
        with self._lock:
            return self._spk_to_address.get(spk_hex.lower().strip())

    def ensure_watched(self, spk_hex: str) -> None:
        spk_hex = normalize_script_hex(spk_hex)
        with self._lock:
            if spk_hex in self._imported_spks:
                return

        script = bytes.fromhex(spk_hex)
        address = self.address_for_spk(spk_hex)
        if address is None:
            try:
                address = bitcoin.script_to_address(script)
            except Exception:
                address = None

        if address:
            desc = add_descriptor_checksum(f"addr({address})")
        else:
            desc = add_descriptor_checksum(f"raw({spk_hex})")

        request = [{
            "desc": desc,
            "timestamp": "now",
            "watchonly": True,
            "keypool": False,
        }]
        results = self.rpc.importdescriptors(request)
        for r in results:
            if not r.get("success"):
                err = r.get("error", {})
                if err.get("code") == -4:
                    break
                raise RPCError(err.get("code", -1), err.get("message", "unknown"))

        sh = scriptpubkey_to_scripthash(script)
        with self._lock:
            self._imported_spks.add(spk_hex)
            self._spk_to_address.setdefault(spk_hex, address)
            self._sh_to_spk[sh] = spk_hex

    def address_for_scripthash(self, scripthash: str) -> Optional[str]:
        spk_hex = self._sh_to_spk.get(scripthash)
        if spk_hex is None:
            return None
        return self._spk_to_address.get(spk_hex)

    def script_for_scripthash(self, scripthash: str) -> Optional[bytes]:
        spk_hex = self._sh_to_spk.get(scripthash)
        if spk_hex is None:
            return None
        return bytes.fromhex(spk_hex)


# ---------------------------------------------------------------------------
# Import management
# ---------------------------------------------------------------------------

class AddressImporter:
    """
    Imports wallet addresses into Bitcoin Core and tracks whether a rescan
    is needed.

    Strategy:
      - Bitcoin Core >= 0.21: use importdescriptors (preferred)
      - Older Core: fall back to importmulti
    """

    def __init__(self, rpc: BitcoinRPC):
        self.rpc = rpc
        self._core_version: Optional[int] = None

    def _get_core_version(self) -> int:
        if self._core_version is None:
            info = self.rpc.getnetworkinfo()
            self._core_version = info["version"]
        return self._core_version

    def _use_descriptors(self) -> bool:
        # importdescriptors available from v0.21.0 (210000)
        return self._get_core_version() >= 210000

    def import_wallet(self, wallet: "Abstract_Wallet",
                      progress_cb=None) -> bool:
        """
        Import all keystores from `wallet` into Bitcoin Core.

        Returns True if a rescan was triggered (i.e. new addresses were
        imported), False if everything was already present.

        `progress_cb(message: str)` is called with status strings if provided.
        """
        keystores = wallet.get_keystores()
        if not keystores:
            raise ValueError("Wallet has no keystores — cannot import.")
        if _is_multisig_wallet(wallet):
            raise ValueError(
                "Multisig wallets are not supported by bulk import. "
                "EPS would import incorrect single-sig addresses for each "
                "cosigner key. Use a single-signature wallet, or rely on "
                "protocol 1.7 on-demand watching instead."
            )

        def progress(msg):
            if progress_cb:
                progress_cb(msg)

        imported_any = False
        for i, ks in enumerate(keystores):
            if not hasattr(ks, 'xpub') or not ks.xpub:
                progress(f"Keystore {i}: skipping (no xpub)")
                continue

            progress(f"Keystore {i}: importing addresses for {ks.xpub[:16]}…")
            newly_imported = self._import_keystore(ks, progress)
            if newly_imported:
                imported_any = True

        return imported_any

    def _import_keystore(self, ks, progress_cb) -> bool:
        """Import one keystore's receiving and change addresses."""
        xpub = ks.xpub
        script_type = _script_type_for_keystore(ks)
        count = IMPORT_ADDRESS_COUNT

        newly_imported = False

        for change in (0, 1):
            branch = "change" if change else "receiving"
            progress_cb(f"  Importing {count} {branch} addresses…")

            if self._use_descriptors():
                result = self._import_via_descriptors(
                    xpub, script_type, change, count)
            else:
                result = self._import_via_importmulti(
                    xpub, script_type, change, count)

            if result:
                newly_imported = True

        return newly_imported

    def _import_via_descriptors(self, xpub: str, script_type: str,
                                 change: int, count: int) -> bool:
        """Use importdescriptors (Core >= 0.21)."""
        xpub = _to_canonical_xpub(xpub)
        tmpl = _XPUB_TYPE_TO_SCRIPT.get(script_type, "pkh")
        if tmpl == "sh(wpkh":
            desc_unwrapped = f"wpkh({xpub}/{change}/*)"
            desc = f"sh({desc_unwrapped})"
        else:
            desc = f"{tmpl}({xpub}/{change}/*)"

        # Bitcoin Core requires a checksum
        desc_with_checksum = add_descriptor_checksum(desc)

        request = [{
            "desc": desc_with_checksum,
            "timestamp": "now",   # only scan from now; rescan separately
            "range": [0, count - 1],
            "watchonly": True,
            "keypool": False,
            "internal": change == 1,
        }]

        try:
            results = self.rpc.importdescriptors(request)
            # results is a list of {success: bool, warnings: [...], error: {...}}
            for r in results:
                if not r.get("success"):
                    err = r.get("error", {})
                    if err.get("code") == -4:
                        # Already imported — not an error for us
                        return False
                    raise RPCError(err.get("code", -1), err.get("message", "unknown"))
            return True
        except RPCError as e:
            if e.code == -4:
                return False  # already imported
            raise

    def _import_via_importmulti(self, xpub: str, script_type: str,
                                 change: int, count: int) -> bool:
        """Fall back to importmulti (Core 0.17–0.20)."""
        node = BIP32Node.from_xkey(xpub, allow_custom_headers=True)
        branch_node = node.subkey_at_public_derivation([change])

        requests = []
        for i in range(count):
            child = branch_node.subkey_at_public_derivation([i])
            pubkey_hex = child.eckey.get_public_key_bytes(compressed=True).hex()

            if script_type == "p2wpkh":
                req = {"scriptPubKey": {"address": bitcoin.pubkey_to_address("p2wpkh", pubkey_hex)}}
            elif script_type == "p2wpkh-p2sh":
                req = {"scriptPubKey": {"address": bitcoin.pubkey_to_address("p2wpkh-p2sh", pubkey_hex)}}
            else:
                req = {"scriptPubKey": {"address": bitcoin.pubkey_to_address("p2pkh", pubkey_hex)}}

            req.update({
                "timestamp": "now",
                "watchonly": True,
                "keypool": False,
            })
            requests.append(req)

        results = self.rpc.importmulti(requests, {"rescan": False})
        return any(r.get("success") for r in results)
