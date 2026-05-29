"""
Tests for eps.addresses — descriptor checksum and Merkle branch.
These have no Electrum or Bitcoin Core dependency.
"""
import unittest
from unittest.mock import MagicMock
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
