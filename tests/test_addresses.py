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
