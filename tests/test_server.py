"""
Tests for eps.server — protocol dispatch, helper methods.
Bitcoin Core RPC is mocked; no real node or Electrum install required.
"""
import json
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
from eps.server import (
    ElectrumServer, ClientState, _merkle_branch, _negotiate_protocol,
    PROTOCOL_VERSION_MIN, PROTOCOL_VERSION_MAX,
)


def _make_server() -> ElectrumServer:
    rpc = MagicMock(spec=BitcoinRPC)
    return ElectrumServer(rpc, host="127.0.0.1", port=50002)


class TestScripthashCache(unittest.TestCase):
    """Verify the cache is per-instance, not class-level."""

    def test_separate_instances_have_separate_caches(self):
        s1 = _make_server()
        s2 = _make_server()
        # Patch address_to_scripthash to return a known value
        with patch("eps.server.address_to_scripthash", return_value="aabb"), \
             patch("eps.addresses.ScriptWatcher.register_address"):
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

    def test_server_ping_17(self):
        state = ClientState()
        state.protocol_version = "1.7"
        t = threading.current_thread()
        self.server._clients[t] = (MagicMock(), state)
        try:
            resp = self._dispatch("server.ping", [32, "aa"])
            self.assertEqual(resp["result"], {"data": "0" * 32})
        finally:
            self.server._clients.pop(t, None)

    def test_server_features_protocol_range(self):
        self.server.rpc.getblockhash.return_value = "00" * 32
        resp = self._dispatch("server.features")
        self.assertEqual(resp["result"]["protocol_min"], PROTOCOL_VERSION_MIN)
        self.assertEqual(resp["result"]["protocol_max"], PROTOCOL_VERSION_MAX)

    def test_protocol_negotiation(self):
        self.assertEqual(_negotiate_protocol(["1.7", "1.7"]), "1.7")
        self.assertEqual(_negotiate_protocol(["1.4", "1.6"]), "1.6")
        self.assertEqual(_negotiate_protocol("1.4"), "1.4")

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
        with patch("eps.server.address_to_scripthash", return_value="testhash"), \
             patch("eps.addresses.ScriptWatcher.register_address"):
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


class TestScriptPubKey(unittest.TestCase):

    def setUp(self):
        self.server = _make_server()
        self.spk = "76a914" + "11" * 20 + "88ac"
        self.sh = "abc123"

    def test_scriptpubkey_subscribe_imports_and_subscribes(self):
        self.server._script_watcher.ensure_watched = MagicMock()
        self.server._spk_status = MagicMock(return_value="deadbeef")
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.scriptpubkey.subscribe",
             "params": [self.spk]},
            "peer",
        )
        self.server._script_watcher.ensure_watched.assert_called_once_with(self.spk)
        self.assertEqual(resp["result"], "deadbeef")

    def test_scriptpubkey_get_balance(self):
        self.server._script_watcher.ensure_watched = MagicMock()
        with patch.object(self.server, "_get_balance", return_value={"confirmed": 1, "unconfirmed": 0}) as mock_bal:
            resp = self.server._dispatch(
                {"id": 1, "method": "blockchain.scriptpubkey.get_balance",
                 "params": [self.spk]},
                "peer",
            )
        mock_bal.assert_called_once_with(spk_hex=self.spk)
        self.assertEqual(resp["result"]["confirmed"], 1)


class TestBlockHeaders(unittest.TestCase):

    def setUp(self):
        self.server = _make_server()

    def test_block_headers_17_format(self):
        state = ClientState()
        state.protocol_version = "1.7"
        t = threading.current_thread()
        self.server._clients[t] = (MagicMock(), state)
        self.server.rpc.getblockcount.return_value = 100
        self.server.rpc.getblockhash.return_value = "blockhash"
        self.server.rpc.getblock.return_value = "aa" * 100
        try:
            resp = self.server._dispatch(
                {"id": 1, "method": "blockchain.block.headers", "params": [90, 3]},
                "peer",
            )
        finally:
            self.server._clients.pop(t, None)
        result = resp["result"]
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["max"], 2016)
        self.assertEqual(len(result["headers"]), 3)
        self.assertEqual(len(result["headers"][0]), 160)

    def test_block_headers_14_format(self):
        state = ClientState()
        state.protocol_version = "1.4"
        t = threading.current_thread()
        self.server._clients[t] = (MagicMock(), state)
        self.server.rpc.getblockcount.return_value = 100
        self.server.rpc.getblockhash.return_value = "blockhash"
        self.server.rpc.getblock.return_value = "bb" * 100
        try:
            resp = self.server._dispatch(
                {"id": 1, "method": "blockchain.block.headers", "params": [0, 2]},
                "peer",
            )
        finally:
            self.server._clients.pop(t, None)
        result = resp["result"]
        self.assertIn("hex", result)
        self.assertNotIn("headers", result)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["max"], 2016)


class TestPushScriptNotifications(unittest.TestCase):
    """H1 regression: each subscription type must be notified with the
    identifier the client subscribed with (scripthash vs scriptPubKey)."""

    def setUp(self):
        self.server = _make_server()
        # Non-empty history → non-None status, so a notification is emitted.
        self.server._get_history = MagicMock(
            return_value=[{"tx_hash": "aa" * 32, "height": 1}])

    @staticmethod
    def _sent(conn):
        return [json.loads(call[0][0].decode())
                for call in conn.sendall.call_args_list]

    def test_scriptpubkey_notification_uses_spk_identifier(self):
        spk = "76a914" + "11" * 20 + "88ac"
        conn = MagicMock()
        state = ClientState()
        state.scriptpubkey_subs.add(spk)
        self.server._clients["c1"] = (conn, state)

        self.server._push_script_notifications()

        msgs = self._sent(conn)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["method"], "blockchain.scriptpubkey.subscribe")
        # The identifier must be the spk hex, NOT its scripthash.
        self.assertEqual(msgs[0]["params"][0], spk)

    def test_scripthash_notification_uses_scripthash_identifier(self):
        sh = "ab" * 32
        conn = MagicMock()
        state = ClientState()
        state.scripthash_subs.add(sh)
        self.server._clients["c1"] = (conn, state)

        self.server._push_script_notifications()

        msgs = self._sent(conn)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["method"], "blockchain.scripthash.subscribe")
        self.assertEqual(msgs[0]["params"][0], sh)

    def test_unchanged_status_not_repushed(self):
        spk = "76a914" + "22" * 20 + "88ac"
        conn = MagicMock()
        state = ClientState()
        state.scriptpubkey_subs.add(spk)
        self.server._clients["c1"] = (conn, state)

        self.server._push_script_notifications()
        self.server._push_script_notifications()  # status cached → no resend

        self.assertEqual(conn.sendall.call_count, 1)


if __name__ == "__main__":
    unittest.main()
