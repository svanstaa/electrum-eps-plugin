"""
Tests for eps.server — protocol dispatch, helper methods.
Bitcoin Core RPC is mocked; no real node or Electrum install required.
"""
import threading
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Stub out the electrum package before our code imports it
for _mod in ("electrum", "electrum.bip32", "electrum.bitcoin"):
    sys.modules.setdefault(_mod, MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eps.rpc import BitcoinRPC, RPCError
from eps.server import ElectrumServer, _merkle_branch


def _make_server() -> ElectrumServer:
    rpc = MagicMock(spec=BitcoinRPC)
    return ElectrumServer(rpc, host="127.0.0.1", port=50002)


class TestScripthashCache(unittest.TestCase):
    """Verify the cache is per-instance, not class-level."""

    def test_separate_instances_have_separate_caches(self):
        s1 = _make_server()
        s2 = _make_server()
        # Patch address_to_scripthash to return a known value
        with patch("eps.server.address_to_scripthash", return_value="aabb"):
            s1.register_address("bc1qfoo")
        self.assertIn("aabb", s1._scripthash_cache)
        self.assertNotIn("aabb", s2._scripthash_cache)


class TestDispatch(unittest.TestCase):

    def setUp(self):
        self.server = _make_server()

    def _dispatch(self, method, params=None):
        req = {"id": 1, "method": method, "params": params or []}
        return self.server._dispatch(req, "127.0.0.1:12345")

    def test_unknown_method(self):
        resp = self._dispatch("nonexistent.method")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_server_ping(self):
        resp = self._dispatch("server.ping")
        self.assertIn("result", resp)
        self.assertIsNone(resp["result"])

    def test_server_version(self):
        resp = self._dispatch("server.version", ["Electrum/4.0", "1.4"])
        self.assertIn("result", resp)
        self.assertIsInstance(resp["result"], list)
        self.assertEqual(len(resp["result"]), 2)

    def test_server_peers_subscribe(self):
        resp = self._dispatch("server.peers.subscribe")
        self.assertEqual(resp["result"], [])

    def test_blockchain_estimatefee(self):
        self.server.rpc.estimatesmartfee.return_value = {"feerate": 0.00012345}
        resp = self._dispatch("blockchain.estimatefee", [6])
        self.assertAlmostEqual(resp["result"], 0.00012345)

    def test_blockchain_estimatefee_no_result(self):
        self.server.rpc.estimatesmartfee.return_value = {}
        resp = self._dispatch("blockchain.estimatefee", [6])
        self.assertEqual(resp["result"], -1)

    def test_blockchain_transaction_broadcast(self):
        self.server.rpc.sendrawtransaction.return_value = "abc123"
        resp = self._dispatch("blockchain.transaction.broadcast", ["deadbeef"])
        self.assertEqual(resp["result"], "abc123")

    def test_mempool_fee_histogram(self):
        resp = self._dispatch("mempool.get_fee_histogram")
        self.assertEqual(resp["result"], [])


class TestGetBalance(unittest.TestCase):

    def setUp(self):
        self.server = _make_server()
        with patch("eps.server.address_to_scripthash", return_value="testhash"):
            self.server.register_address("bc1qtest")

    def test_balance_sums_utxos(self):
        self.server.rpc.listunspent.side_effect = [
            # confirmed (minconf=1)
            [{"amount": 0.5}, {"amount": 0.25}],
            # unconfirmed (minconf=0, maxconf=0)
            [{"amount": 0.01}],
        ]
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.scripthash.get_balance",
             "params": ["testhash"]},
            "peer"
        )
        self.assertEqual(resp["result"]["confirmed"], 75_000_000)
        self.assertEqual(resp["result"]["unconfirmed"], 1_000_000)

    def test_balance_unknown_scripthash(self):
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.scripthash.get_balance",
             "params": ["unknown"]},
            "peer"
        )
        self.assertEqual(resp["result"], {"confirmed": 0, "unconfirmed": 0})


class TestGetMerkle(unittest.TestCase):

    def setUp(self):
        self.server = _make_server()

    def test_get_merkle_known_tx(self):
        txids = [hex(i)[2:].zfill(64) for i in range(4)]
        self.server.rpc.getblockhash.return_value = "blockhash"
        self.server.rpc.getblock.return_value = {"tx": txids}
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.transaction.get_merkle",
             "params": [txids[2], 800000]},
            "peer"
        )
        result = resp["result"]
        self.assertEqual(result["pos"], 2)
        self.assertEqual(result["block_height"], 800000)
        self.assertIsInstance(result["merkle"], list)
        self.assertEqual(len(result["merkle"]), 2)  # log2(4) = 2

    def test_get_merkle_tx_not_in_block(self):
        self.server.rpc.getblockhash.return_value = "blockhash"
        self.server.rpc.getblock.return_value = {"tx": ["a" * 64]}
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.transaction.get_merkle",
             "params": ["b" * 64, 1]},
            "peer"
        )
        self.assertIn("error", resp)


if __name__ == "__main__":
    unittest.main()
