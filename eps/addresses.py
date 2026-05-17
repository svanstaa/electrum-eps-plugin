# eps_plugin/addresses.py
#
# Derives addresses from an Electrum wallet's keystores and manages
# their import into Bitcoin Core via descriptors or importmulti.

import hashlib
from typing import Iterator, List, Tuple, Optional, TYPE_CHECKING

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


def _descriptor_for_xpub(xpub: str, script_type: str,
                          change: int, start: int, end: int) -> str:
    """
    Build a Bitcoin Core output descriptor for a range of addresses.

    e.g. wpkh([fingerprint/84h/0h/0h]xpub.../0/0:99)
    """
    tmpl = _XPUB_TYPE_TO_SCRIPT.get(script_type, "pkh")
    path = f"{xpub}/{change}/{start}:{end}"

    if tmpl == "sh(wpkh":
        return f"sh(wpkh({path}))"
    return f"{tmpl}({path})"


def derive_addresses(ks, change: int, count: int) -> List[str]:
    """
    Derive `count` addresses from keystore `ks` on branch `change`
    (0 = receiving, 1 = change) using Electrum's own BIP32 code.
    """
    node = BIP32Node.from_xkey(ks.xpub)
    branch_node = node.subkey_at_public_derivation([change])
    script_type = _script_type_for_keystore(ks)

    addresses = []
    for i in range(count):
        child = branch_node.subkey_at_public_derivation([i])
        pubkey_bytes = child.eckey.get_public_key_bytes(compressed=True)

        if script_type == "p2wpkh":
            addr = bitcoin.pubkey_to_address("p2wpkh", pubkey_bytes.hex())
        elif script_type == "p2wpkh-p2sh":
            addr = bitcoin.pubkey_to_address("p2wpkh-p2sh", pubkey_bytes.hex())
        else:
            addr = bitcoin.pubkey_to_address("p2pkh", pubkey_bytes.hex())

        addresses.append(addr)
    return addresses


def address_to_scripthash(address: str) -> str:
    """
    Convert a Bitcoin address to the reversed SHA256 scripthash format
    used by the Electrum protocol.
    """
    script = bitcoin.address_to_script(address)
    # Newer Electrum returns bytes; older versions returned a hex string.
    if isinstance(script, str):
        script = bytes.fromhex(script)
    digest = hashlib.sha256(script).digest()
    return digest[::-1].hex()


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

    def __init__(self, rpc: BitcoinRPC, gap_limit: int = 20):
        self.rpc = rpc
        self.gap_limit = gap_limit
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
        count = self.gap_limit + 50  # import generously

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
        desc_with_checksum = self._add_descriptor_checksum(desc)

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

    # ------------------------------------------------------------------
    # Descriptor checksum (required by Core >= 0.20)
    # Ported from bitcoin/src/script/descriptor.cpp
    # ------------------------------------------------------------------

    @staticmethod
    def _add_descriptor_checksum(desc: str) -> str:
        INPUT_CHARSET = (
            "0123456789()[],'/*abcdefgh@:$%{}"
            "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
            "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
        )
        CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        def _poly_mod(c, val):
            c0 = c >> 35
            c = ((c & 0x7FFFFFFFF) << 5) ^ val
            if c0 & 1: c ^= 0xF5DEE51989
            if c0 & 2: c ^= 0xA9FDCA3312
            if c0 & 4: c ^= 0x1BAB10E32D
            if c0 & 8: c ^= 0x3706B1677A
            if c0 & 16: c ^= 0x644D626FFD
            return c

        c = 1
        cls = 0
        cls_count = 0
        for ch in desc:
            pos = INPUT_CHARSET.find(ch)
            if pos < 0:
                return desc  # invalid character — return without checksum
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
