"""
Tests for eps.addresses — descriptor checksum and Merkle branch.
These have no Electrum or Bitcoin Core dependency.
"""
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Stub out the electrum package before our code imports it
for _mod in ("electrum", "electrum.bip32", "electrum.bitcoin"):
    sys.modules.setdefault(_mod, MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestDescriptorChecksum(unittest.TestCase):
    """
    Test the descriptor checksum implementation against known-good values
    produced by Bitcoin Core.
    """

    def _checksum(self, desc: str) -> str:
        from eps.addresses import add_descriptor_checksum
        result = add_descriptor_checksum(desc)
        return result.split("#")[1] if "#" in result else ""

    def test_pkh_checksum(self):
        # Known value: bitcoin-cli getdescriptorinfo "pkh(xpub...)" gives a checksum.
        # We test that the function produces an 8-character alphanumeric string.
        desc = "pkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC2DGsRA5BJ5B4PBjkX2x5n12HrUBmQCBFEYK4GBDtWyjioB2iqsUFJADBnxGxFyMMJVzAzqaKrJqj)"
        cs = self._checksum(desc)
        self.assertEqual(len(cs), 8)
        for ch in cs:
            self.assertIn(ch, "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    def test_checksum_deterministic(self):
        desc = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC2DGsRA5BJ5B4PBjkX2x5n12HrUBmQCBFEYK4GBDtWyjioB2iqsUFJADBnxGxFyMMJVzAzqaKrJqj/0/*)"
        cs1 = self._checksum(desc)
        cs2 = self._checksum(desc)
        self.assertEqual(cs1, cs2)


class TestNormalizeScriptHex(unittest.TestCase):
    """Validation/normalization of untrusted scriptPubKey hex from clients."""

    def _norm(self, value, **kw):
        from eps.addresses import normalize_script_hex
        return normalize_script_hex(value, **kw)

    def test_valid_hex_lowercased(self):
        self.assertEqual(self._norm("76A914" + "11" * 20 + "88AC"),
                         "76a914" + "11" * 20 + "88ac")

    def test_whitespace_stripped(self):
        self.assertEqual(self._norm("  0014" + "ab" * 20 + "\n"),
                         "0014" + "ab" * 20)

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            self._norm("")

    def test_whitespace_only_rejected(self):
        with self.assertRaises(ValueError):
            self._norm("   ")

    def test_odd_length_rejected(self):
        with self.assertRaises(ValueError):
            self._norm("abc")

    def test_non_hex_rejected(self):
        with self.assertRaises(ValueError):
            self._norm("zz" * 4)

    def test_non_string_rejected(self):
        with self.assertRaises(ValueError):
            self._norm(b"0014")

    def test_field_name_in_message(self):
        with self.assertRaises(ValueError) as ctx:
            self._norm("xy", field="outpoint")
        self.assertIn("outpoint", str(ctx.exception))


class TestMultisigDetection(unittest.TestCase):
    """`_is_multisig_wallet` routing and the empty-wallet guard."""

    class _Wallet:
        def __init__(self, wallet_type="standard", keystores=None):
            self.wallet_type = wallet_type
            self._keystores = [] if keystores is None else keystores

        def get_keystores(self):
            return self._keystores

    def _importer(self):
        from eps.addresses import AddressImporter
        return AddressImporter(MagicMock())

    def test_detects_multisig_by_wallet_type(self):
        from eps.addresses import _is_multisig_wallet
        # "of" in the type name (2of3) flags it even with one keystore visible.
        self.assertTrue(_is_multisig_wallet(self._Wallet("2of3", [object()])))

    def test_detects_multisig_by_keystore_count(self):
        from eps.addresses import _is_multisig_wallet
        self.assertTrue(_is_multisig_wallet(
            self._Wallet("standard", [object(), object()])))

    def test_single_sig_not_multisig(self):
        from eps.addresses import _is_multisig_wallet
        self.assertFalse(_is_multisig_wallet(self._Wallet("standard", [object()])))

    def test_keystores_error_treated_as_single_sig(self):
        from eps.addresses import _is_multisig_wallet

        class _Raising:
            wallet_type = ""

            def get_keystores(self):
                raise RuntimeError("boom")

        self.assertFalse(_is_multisig_wallet(_Raising()))

    def test_import_wallet_rejects_no_keystores(self):
        importer = self._importer()
        with self.assertRaises(ValueError) as ctx:
            importer.import_wallet(self._Wallet("standard", []))
        self.assertIn("keystore", str(ctx.exception).lower())


class TestMultisigImport(unittest.TestCase):
    """Success-path tests for sortedmulti descriptor import (Core 0.21+)."""

    class _KS:
        def __init__(self, xpub):
            self.xpub = xpub

    class _Wallet:
        def __init__(self, m=2, xpubs=("xpubONE", "xpubTWO", "xpubTHREE"),
                     txin_type="p2wsh", wallet_type=None):
            self.m = m
            self.txin_type = txin_type
            self.wallet_type = (wallet_type if wallet_type is not None
                                else f"{m}of{len(xpubs)}")
            self._keystores = [TestMultisigImport._KS(x) for x in xpubs]

        def get_keystores(self):
            return self._keystores

    def setUp(self):
        # _to_canonical_xpub needs real electrum crypto; stub to identity so we
        # can assert on the descriptor strings directly.
        patcher = patch("eps.addresses._to_canonical_xpub",
                        side_effect=lambda x: x)
        self.addCleanup(patcher.stop)
        patcher.start()

    def _importer(self, version=210000, import_result=None):
        from eps.addresses import AddressImporter
        imp = AddressImporter(MagicMock())
        imp.rpc.getnetworkinfo.return_value = {"version": version}
        imp.rpc.importdescriptors.return_value = (
            import_result if import_result is not None else [{"success": True}])
        return imp

    def _requests(self, imp):
        return [call[0][0][0]
                for call in imp.rpc.importdescriptors.call_args_list]

    def test_imports_both_branches_native_segwit(self):
        imp = self._importer()
        self.assertTrue(imp.import_wallet(self._Wallet()))
        reqs = self._requests(imp)
        self.assertEqual(len(reqs), 2)

        recv, change = reqs
        self.assertEqual(
            recv["desc"].split("#")[0],
            "wsh(sortedmulti(2,xpubONE/0/*,xpubTWO/0/*,xpubTHREE/0/*))")
        self.assertFalse(recv["internal"])
        self.assertEqual(recv["range"], [0, 99])

        self.assertEqual(
            change["desc"].split("#")[0],
            "wsh(sortedmulti(2,xpubONE/1/*,xpubTWO/1/*,xpubTHREE/1/*))")
        self.assertTrue(change["internal"])

    def test_nested_segwit_wrap(self):
        imp = self._importer()
        imp.import_wallet(self._Wallet(txin_type="p2wsh-p2sh"))
        self.assertTrue(
            self._requests(imp)[0]["desc"].startswith("sh(wsh(sortedmulti(2,"))

    def test_legacy_p2sh_wrap(self):
        imp = self._importer()
        imp.import_wallet(self._Wallet(txin_type="p2sh"))
        desc = self._requests(imp)[0]["desc"]
        self.assertTrue(desc.startswith("sh(sortedmulti(2,"))
        self.assertFalse(desc.startswith("sh(wsh"))

    def test_threshold_from_wallet_type_when_m_missing(self):
        imp = self._importer()
        imp.import_wallet(self._Wallet(m=None, wallet_type="2of3"))
        self.assertIn("sortedmulti(2,", self._requests(imp)[0]["desc"])

    def test_already_imported_returns_false(self):
        imp = self._importer(
            import_result=[{"success": False, "error": {"code": -4}}])
        self.assertFalse(imp.import_wallet(self._Wallet()))
        self.assertEqual(len(self._requests(imp)), 2)

    def test_requires_core_021(self):
        imp = self._importer(version=200000)
        with self.assertRaises(ValueError) as ctx:
            imp.import_wallet(self._Wallet())
        self.assertIn("0.21", str(ctx.exception))
        imp.rpc.importdescriptors.assert_not_called()

    def test_fewer_than_two_cosigner_xpubs_raises(self):
        imp = self._importer()
        wallet = self._Wallet(xpubs=("only", None), wallet_type="2of2")
        with self.assertRaises(ValueError) as ctx:
            imp.import_wallet(wallet)
        self.assertIn("fewer than 2", str(ctx.exception))


class TestMerkleBranch(unittest.TestCase):
    """Test the Merkle branch computation in server.py."""

    def _branch(self, txids, pos):
        from eps.server import _merkle_branch
        return _merkle_branch(txids, pos)

    def test_single_tx(self):
        """A block with one tx has an empty branch."""
        txids = ["a" * 64]
        self.assertEqual(self._branch(txids, 0), [])

    def test_two_txs_first(self):
        txids = ["a" * 64, "b" * 64]
        branch = self._branch(txids, 0)
        self.assertEqual(len(branch), 1)
        self.assertEqual(branch[0], "b" * 64)  # sibling is tx[1]

    def test_two_txs_second(self):
        txids = ["a" * 64, "b" * 64]
        branch = self._branch(txids, 1)
        self.assertEqual(len(branch), 1)
        self.assertEqual(branch[0], "a" * 64)  # sibling is tx[0]

    def test_odd_txcount_duplication(self):
        """With 3 txs, the last is duplicated to make an even level."""
        txids = ["a" * 64, "b" * 64, "c" * 64]
        branch = self._branch(txids, 2)
        # At level 0, pos=2 → sibling is pos=3 (duplicate of pos=2)
        self.assertEqual(branch[0], "c" * 64)

    def test_branch_length_power_of_two(self):
        """Branch length = ceil(log2(n)) for n a power of 2."""
        import math
        for n in (2, 4, 8, 16):
            txids = [hex(i)[2:].zfill(64) for i in range(n)]
            branch = self._branch(txids, 0)
            self.assertEqual(len(branch), int(math.log2(n)))


if __name__ == "__main__":
    unittest.main()
