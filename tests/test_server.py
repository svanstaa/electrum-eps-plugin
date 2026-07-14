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
    ElectrumServer, ClientState, MempoolIndex, _merkle_branch,
    _negotiate_protocol, PROTOCOL_VERSION_MIN, PROTOCOL_VERSION_MAX,
)


def _make_server() -> ElectrumServer:
    rpc = MagicMock(spec=BitcoinRPC)
    return ElectrumServer(rpc, host="127.0.0.1", port=50002)


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

    def test_server_ping_no_params(self):
        resp = self._dispatch("server.ping")
        self.assertEqual(resp["result"], {"data": ""})

    def test_server_ping_pong_len(self):
        resp = self._dispatch("server.ping", [32, "aa"])
        self.assertEqual(resp["result"], {"data": "0" * 32})

    def test_server_features_protocol_range(self):
        self.server.rpc.getblockhash.return_value = "00" * 32
        resp = self._dispatch("server.features")
        self.assertEqual(resp["result"]["protocol_min"], PROTOCOL_VERSION_MIN)
        self.assertEqual(resp["result"]["protocol_max"], PROTOCOL_VERSION_MAX)

    def test_protocol_negotiation(self):
        # 1.7-only server: older clients cannot negotiate a session.
        from eps.server import ElectrumServerError
        self.assertEqual(_negotiate_protocol(["1.7", "1.7"]), "1.7")
        self.assertEqual(_negotiate_protocol(["1.4", "1.7"]), "1.7")
        with self.assertRaises(ElectrumServerError):
            _negotiate_protocol(["1.4", "1.6"])
        with self.assertRaises(ElectrumServerError):
            _negotiate_protocol("1.4")

    def test_server_version(self):
        resp = self._dispatch("server.version", ["Electrum/4.0", "1.7"])
        self.assertIn("result", resp)
        self.assertIsInstance(resp["result"], list)
        self.assertEqual(resp["result"][1], "1.7")

    def test_server_version_legacy_client_rejected(self):
        resp = self._dispatch("server.version", ["Electrum/4.8", ["1.4", "1.6"]])
        self.assertIn("error", resp)

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
        self.spk = "0014" + "11" * 20
        self.server._script_watcher.ensure_watched = MagicMock()
        self.server._script_watcher.address_for_spk = MagicMock(
            return_value="bc1qtest")

    def test_balance_sums_utxos(self):
        self.server.rpc.listunspent.side_effect = [
            # confirmed (minconf=1)
            [{"amount": 0.5}, {"amount": 0.25}],
            # unconfirmed (minconf=0, maxconf=0)
            [{"amount": 0.01}],
        ]
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.scriptpubkey.get_balance",
             "params": [self.spk]},
            "peer"
        )
        self.assertEqual(resp["result"]["confirmed"], 75_000_000)
        self.assertEqual(resp["result"]["unconfirmed"], 1_000_000)


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

    def test_scriptpubkey_get_history_wrapped_in_dict(self):
        # Finalized 1.7 wraps the history list in {"history": [...]}.
        self.server._script_watcher.ensure_watched = MagicMock()
        hist = [{"tx_hash": "aa" * 32, "height": 5}]
        with patch.object(self.server, "_get_history", return_value=hist):
            resp = self.server._dispatch(
                {"id": 1, "method": "blockchain.scriptpubkey.get_history",
                 "params": [self.spk]},
                "peer",
            )
        self.assertEqual(resp["result"], {"history": hist})

    def test_scriptpubkey_listunspent_wrapped_in_dict(self):
        # Finalized 1.7 wraps the utxo list in {"utxos": [...]}.
        self.server._script_watcher.ensure_watched = MagicMock()
        utxos = [{"tx_hash": "bb" * 32, "tx_pos": 0, "height": 5, "value": 1000}]
        with patch.object(self.server, "_listunspent", return_value=utxos):
            resp = self.server._dispatch(
                {"id": 1, "method": "blockchain.scriptpubkey.listunspent",
                 "params": [self.spk]},
                "peer",
            )
        self.assertEqual(resp["result"], {"utxos": utxos})

    def test_outpoint_subscribe_funder_height_and_spk_hint(self):
        # Finalized 1.7: status field is "funder_height" (renamed from
        # "height"), and the client always sends an spk_hint third param
        # which the server should import.
        self.server._script_watcher.ensure_watched = MagicMock()
        self.server.rpc.call = MagicMock(return_value={"confirmations": 3})
        self.server._tip_height = 100
        resp = self.server._dispatch(
            {"id": 1, "method": "blockchain.outpoint.subscribe",
             "params": ["cc" * 32, 0, self.spk]},
            "peer",
        )
        self.server._script_watcher.ensure_watched.assert_called_once_with(self.spk)
        self.assertEqual(resp["result"], {"funder_height": 98})
        self.assertNotIn("height", resp["result"])


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

class TestMempoolIndex(unittest.TestCase):
    """The index tracks unconfirmed *wallet* txs keyed by every scriptPubKey
    they touch, so history queries no longer walk the whole mempool."""

    SPK_OUT = "0014" + "aa" * 20
    SPK_PREV = "0014" + "bb" * 20
    TXID = "11" * 32
    PREV_TXID = "22" * 32

    def _make_index(self, unconfirmed_txids, gettxout=None):
        rpc = MagicMock(spec=BitcoinRPC)

        def _call(method, *params):
            if method == "listsinceblock":
                return {"transactions": [
                    {"txid": txid, "confirmations": 0}
                    for txid in unconfirmed_txids]}
            if method == "gettxout":
                return gettxout
            raise AssertionError(f"unexpected RPC {method}")

        rpc.call.side_effect = _call
        rpc.getrawtransaction.return_value = {
            "vout": [{"scriptPubKey": {"hex": self.SPK_OUT}}],
            "vin": [{"txid": self.PREV_TXID, "vout": 0}],
        }
        return MempoolIndex(rpc)

    def test_indexes_output_spk(self):
        idx = self._make_index([self.TXID])
        self.assertEqual(idx.txids_for_spk(self.SPK_OUT), {self.TXID})
        self.assertEqual(idx.txids_for_spk("0014" + "cc" * 20), set())

    def test_indexes_prevout_spk_via_gettxout(self):
        idx = self._make_index(
            [self.TXID],
            gettxout={"scriptPubKey": {"hex": self.SPK_PREV}})
        self.assertEqual(idx.txids_for_spk(self.SPK_PREV), {self.TXID})

    def test_prevout_fallback_to_getrawtransaction(self):
        # gettxout returns None (unconfirmed parent); the raw parent tx is
        # fetched instead. Parent's vout[0] carries SPK_PREV.
        idx = self._make_index([self.TXID], gettxout=None)

        def _getraw(txid, verbose):
            if txid == self.TXID:
                return {
                    "vout": [{"scriptPubKey": {"hex": self.SPK_OUT}}],
                    "vin": [{"txid": self.PREV_TXID, "vout": 0}],
                }
            return {"vout": [{"scriptPubKey": {"hex": self.SPK_PREV}}]}

        idx.rpc.getrawtransaction.side_effect = _getraw
        self.assertEqual(idx.txids_for_spk(self.SPK_PREV), {self.TXID})

    def test_coinbase_input_skipped(self):
        idx = self._make_index([self.TXID])
        idx.rpc.getrawtransaction.return_value = {
            "vout": [{"scriptPubKey": {"hex": self.SPK_OUT}}],
            "vin": [{"coinbase": "00"}],   # no txid/vout keys
        }
        self.assertEqual(idx.txids_for_spk(self.SPK_OUT), {self.TXID})

    def test_evicts_confirmed_tx(self):
        idx = self._make_index([self.TXID])
        self.assertEqual(idx.txids_for_spk(self.SPK_OUT), {self.TXID})

        # Tx confirmed: listsinceblock no longer reports it unconfirmed.
        def _call(method, *params):
            if method == "listsinceblock":
                return {"transactions": [
                    {"txid": self.TXID, "confirmations": 1}]}
            return None
        idx.rpc.call.side_effect = _call
        idx._last_refresh = 0.0   # force refresh past the TTL
        self.assertEqual(idx.txids_for_spk(self.SPK_OUT), set())

    def test_ttl_prevents_repeated_refresh(self):
        idx = self._make_index([self.TXID])
        idx.txids_for_spk(self.SPK_OUT)
        idx.txids_for_spk(self.SPK_OUT)
        calls = [c for c in idx.rpc.call.call_args_list
                 if c[0][0] == "listsinceblock"]
        self.assertEqual(len(calls), 1)

    def test_history_includes_indexed_mempool_tx(self):
        # Integration: _get_history picks up the indexed unconfirmed tx and
        # decorates it with the mempool fee, per protocol requirements.
        server = _make_server()
        spk = self.SPK_OUT
        server._script_watcher.address_for_spk = MagicMock(return_value=None)
        server.rpc.listunspent.return_value = []
        server._mempool_index.txids_for_spk = MagicMock(
            return_value={self.TXID})
        server.rpc.call.side_effect = lambda method, *p: (
            {"fees": {"base": 0.00001}, "ancestorcount": 1}
            if method == "getmempoolentry" else None)

        history = server._get_history(spk_hex=spk)
        self.assertEqual(history, [
            {"tx_hash": self.TXID, "height": 0, "fee": 1000}])


class TestPushScriptNotifications(unittest.TestCase):
    """Notification identifiers per finalized protocol 1.7: scriptpubkey
    subs are keyed by scripthash(spk) — Electrum's interface converts
    spk -> sh for matching."""

    def setUp(self):
        self.server = _make_server()
        # Non-empty history → non-None status, so a notification is emitted.
        self.server._get_history = MagicMock(
            return_value=[{"tx_hash": "aa" * 32, "height": 1}])

    @staticmethod
    def _sent(conn):
        return [json.loads(call[0][0].decode())
                for call in conn.sendall.call_args_list]

    def test_scriptpubkey_notification_uses_scripthash_of_spk(self):
        spk = "76a914" + "11" * 20 + "88ac"
        conn = MagicMock()
        state = ClientState()
        state.scriptpubkey_subs.add(spk)
        self.server._clients["c1"] = (conn, state)

        self.server._push_script_notifications()

        msgs = self._sent(conn)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["method"], "blockchain.scriptpubkey.subscribe")
        # Finalized 1.7: the identifier is scripthash(spk), not the spk hex.
        from eps.addresses import scriptpubkey_to_scripthash
        self.assertEqual(msgs[0]["params"][0], scriptpubkey_to_scripthash(spk))
        self.assertNotEqual(msgs[0]["params"][0], spk)

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
