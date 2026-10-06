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
    ElectrumServer, ClientState, WalletTxIndex, _merkle_branch,
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

class TestTransactionGet(unittest.TestCase):
    """blockchain.transaction.get must not depend on -txindex: wallet txs are
    served via gettransaction, with getrawtransaction only as a fallback."""

    TXID = "33" * 32

    def setUp(self):
        self.server = _make_server()

    def _dispatch(self, params):
        return self.server._dispatch(
            {"id": 1, "method": "blockchain.transaction.get", "params": params},
            "peer")

    def test_wallet_tx_served_from_gettransaction(self):
        self.server.rpc.call.return_value = {"hex": "beef", "confirmations": 3}
        resp = self._dispatch([self.TXID])
        self.assertEqual(resp["result"], "beef")
        self.server.rpc.call.assert_called_once_with(
            "gettransaction", self.TXID, True, False)
        self.server.rpc.getrawtransaction.assert_not_called()

    def test_non_wallet_tx_falls_back_to_getrawtransaction(self):
        self.server.rpc.call.side_effect = RPCError(
            -5, "Invalid or non-wallet transaction id")
        self.server.rpc.getrawtransaction.return_value = "cafe"
        resp = self._dispatch([self.TXID])
        self.assertEqual(resp["result"], "cafe")
        self.server.rpc.getrawtransaction.assert_called_once_with(self.TXID, False)

    def test_verbose_composes_decoded_with_wallet_metadata(self):
        self.server.rpc.call.return_value = {
            "hex": "beef", "confirmations": 3, "blockhash": "bh",
            "blockheight": 98, "blocktime": 1700000000, "time": 1699999999,
            "decoded": {"txid": self.TXID, "vout": []},
        }
        resp = self._dispatch([self.TXID, True])
        self.server.rpc.call.assert_called_once_with(
            "gettransaction", self.TXID, True, True)
        result = resp["result"]
        self.assertEqual(result["txid"], self.TXID)
        self.assertEqual(result["hex"], "beef")
        self.assertEqual(result["confirmations"], 3)
        self.assertEqual(result["blockhash"], "bh")


class TestUtxoMatchesSpk(unittest.TestCase):

    def test_matches_on_listunspent_scriptpubkey_field_without_rpc(self):
        spk = "0014" + "ab" * 20
        self.assertTrue(ElectrumServer._utxo_matches_spk(
            {"scriptPubKey": spk.upper(), "txid": "x", "vout": 0}, spk))
        self.assertFalse(ElectrumServer._utxo_matches_spk(
            {"scriptPubKey": "0014" + "cd" * 20}, spk))
        self.assertFalse(ElectrumServer._utxo_matches_spk({}, spk))


class _FakeCore:
    """Just enough of Core's wallet/node RPCs for WalletTxIndex.

    wallet_txs: txid -> {"confirmations", "blockheight"?, "decoded", "from_me"?}
    mempool:    txid -> getmempoolentry result
    utxos:      (txid, n) -> scriptPubKey hex    (gettxout, unspent only)
    raw:        txid -> decoded tx                (getrawtransaction)
    """

    def __init__(self):
        self.wallet_txs = {}
        self.mempool = {}
        self.utxos = {}
        self.raw = {}
        self.removed = []
        self.lastblock = "tip0"
        self.calls = []
        self.rpc = MagicMock(spec=BitcoinRPC)
        self.rpc.call.side_effect = self._call
        self.rpc.getrawtransaction.side_effect = self._getraw
        self.rpc.getblockcount.return_value = 100

    def add_tx(self, txid, *, vouts=(), vins=(), confirmations=0,
               blockheight=None, from_me=False):
        decoded = {
            "txid": txid,
            "vout": [{"n": i, "scriptPubKey": {"hex": spk}}
                     for i, spk in enumerate(vouts)],
            "vin": [({"coinbase": "00"} if v is None
                     else {"txid": v[0], "vout": v[1]}) for v in vins],
        }
        entry = {"confirmations": confirmations, "decoded": decoded,
                 "from_me": from_me}
        if blockheight is not None:
            entry["blockheight"] = blockheight
        self.wallet_txs[txid] = entry

    def method_calls(self, method):
        return [c for c in self.calls if c[0] == method]

    def _call(self, method, *params):
        self.calls.append((method,) + params)
        if method == "listsinceblock":
            txs = []
            for txid, v in self.wallet_txs.items():
                e = {"txid": txid, "confirmations": v["confirmations"]}
                if "blockheight" in v:
                    e["blockheight"] = v["blockheight"]
                txs.append(e)
            return {"transactions": txs, "removed": list(self.removed),
                    "lastblock": self.lastblock}
        if method == "gettransaction":
            v = self.wallet_txs.get(params[0])
            if v is None:
                raise RPCError(-5, "Invalid or non-wallet transaction id")
            out = {"txid": params[0], "hex": "00", "decoded": v["decoded"],
                   "confirmations": v["confirmations"]}
            if v["from_me"]:
                out["fee"] = -0.00001
            return out
        if method == "getmempoolentry":
            if params[0] not in self.mempool:
                raise RPCError(-5, "Transaction not in mempool")
            return self.mempool[params[0]]
        if method == "gettxout":
            spk = self.utxos.get((params[0], params[1]))
            return {"scriptPubKey": {"hex": spk}} if spk else None
        raise AssertionError(f"unexpected RPC {method}")

    def _getraw(self, txid, verbose=False):
        if txid in self.raw:
            return self.raw[txid]
        raise RPCError(-5, "No such mempool transaction. Use -txindex ...")


class TestWalletTxIndex(unittest.TestCase):
    """The index attributes every wallet tx to the scripts it pays to *and*
    spends from, which Core's listsinceblock cannot do (send entries carry
    the destination address; change outputs are omitted)."""

    SPK_A = "0014" + "aa" * 20
    SPK_B = "0014" + "bb" * 20
    SPK_X = "0014" + "ee" * 20     # external destination
    P = "11" * 32                  # parent, pays SPK_A
    T = "22" * 32                  # spends P:0 -> SPK_X (+ change SPK_B)
    F = "33" * 32                  # foreign parent (not a wallet tx)

    def setUp(self):
        self.core = _FakeCore()
        self.idx = WalletTxIndex(self.core.rpc)

    def _hist(self, spk):
        return sorted(self.idx.history_for_spk(spk))

    def _force_refresh(self):
        self.idx._last_refresh = 0.0

    def test_confirmed_receive_indexed_by_output_spk(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], vins=[(self.F, 0)],
                         confirmations=11, blockheight=90)
        self.assertEqual(self._hist(self.SPK_A), [(self.P, 90, None)])
        self.assertEqual(self._hist(self.SPK_B), [])

    def test_confirmed_spend_attributed_to_spent_script(self):
        # The H1 regression: once T confirms it must still appear in SPK_A's
        # history (it spends P:0 which paid SPK_A) and in the change script's.
        self.core.add_tx(self.P, vouts=[self.SPK_A], vins=[(self.F, 0)],
                         confirmations=11, blockheight=90)
        self.core.add_tx(self.T, vouts=[self.SPK_X, self.SPK_B],
                         vins=[(self.P, 0)], confirmations=6, blockheight=95,
                         from_me=True)
        self.assertEqual(self._hist(self.SPK_A),
                         [(self.P, 90, None), (self.T, 95, None)])
        self.assertEqual(self._hist(self.SPK_B), [(self.T, 95, None)])
        self.assertEqual(self._hist(self.SPK_X), [(self.T, 95, None)])

    def test_confirmed_receive_skips_foreign_input_lookups(self):
        # No 'fee' in gettransaction => no input is ours; a confirmed tx must
        # not issue per-input lookups that would only fail without txindex.
        self.core.add_tx(self.P, vouts=[self.SPK_A],
                         vins=[(self.F, 0), (self.F, 1)],
                         confirmations=1, blockheight=100)
        self._hist(self.SPK_A)
        gettx = self.core.method_calls("gettransaction")
        self.assertEqual([c[1] for c in gettx], [self.P])
        self.assertEqual(self.core.method_calls("gettxout"), [])
        self.core.rpc.getrawtransaction.assert_not_called()

    def test_unconfirmed_spend_resolves_prevout_via_gettxout(self):
        # Wallet doesn't know the parent (imported with timestamp 'now'), but
        # while T is unconfirmed the prevout is still in the UTXO set.
        self.core.add_tx(self.T, vouts=[self.SPK_X], vins=[(self.F, 0)],
                         confirmations=0)
        self.core.mempool[self.T] = {"fees": {"base": 0.00001}, "ancestorcount": 1}
        self.core.utxos[(self.F, 0)] = self.SPK_A
        self.assertEqual(self._hist(self.SPK_A), [(self.T, 0, 1000)])

    def test_unconfirmed_spend_falls_back_to_getrawtransaction(self):
        # Unconfirmed parent: not a wallet tx, not in the UTXO set, but in
        # the mempool so getrawtransaction works without txindex.
        self.core.add_tx(self.T, vouts=[self.SPK_X], vins=[(self.F, 1)],
                         confirmations=0)
        self.core.mempool[self.T] = {"fees": {"base": 0.00002}, "ancestorcount": 2}
        self.core.raw[self.F] = {"vout": [
            {"scriptPubKey": {"hex": self.SPK_B}},
            {"scriptPubKey": {"hex": self.SPK_A}}]}
        self.assertEqual(self._hist(self.SPK_A), [(self.T, -1, 2000)])
        self.assertEqual(self._hist(self.SPK_B), [])   # wrong vout

    def test_coinbase_input_skipped(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], vins=[None],
                         confirmations=0)
        self.core.mempool[self.P] = {"fees": {"base": 0}, "ancestorcount": 1}
        self.assertEqual(self._hist(self.SPK_A), [(self.P, 0, 0)])

    def test_unconfirmed_tx_missing_from_mempool_is_excluded(self):
        # confirmations == 0 but not in the mempool: abandoned or replaced.
        self.core.add_tx(self.T, vouts=[self.SPK_A], confirmations=0)
        self.assertEqual(self._hist(self.SPK_A), [])

    def test_conflicted_tx_evicted(self):
        self.core.add_tx(self.T, vouts=[self.SPK_A], confirmations=2,
                         blockheight=99)
        self.assertEqual(self._hist(self.SPK_A), [(self.T, 99, None)])
        self.core.wallet_txs[self.T]["confirmations"] = -1
        self._force_refresh()
        self.assertEqual(self._hist(self.SPK_A), [])

    def test_confirming_updates_height_without_redecoding(self):
        self.core.add_tx(self.T, vouts=[self.SPK_A], confirmations=0)
        self.core.mempool[self.T] = {"fees": {"base": 0.00001}, "ancestorcount": 1}
        self.assertEqual(self._hist(self.SPK_A), [(self.T, 0, 1000)])

        self.core.wallet_txs[self.T].update(confirmations=1, blockheight=100)
        del self.core.mempool[self.T]
        self._force_refresh()
        self.assertEqual(self._hist(self.SPK_A), [(self.T, 100, None)])
        self.assertEqual(len(self.core.method_calls("gettransaction")), 1)

    def test_reorged_out_tx_evicted_via_removed(self):
        self.core.add_tx(self.T, vouts=[self.SPK_A], confirmations=1,
                         blockheight=100)
        self._hist(self.SPK_A)
        del self.core.wallet_txs[self.T]
        self.core.removed = [{"txid": self.T, "confirmations": -1}]
        self._force_refresh()
        self.assertEqual(self._hist(self.SPK_A), [])

    def test_purged_unconfirmed_tx_evicted(self):
        self.core.add_tx(self.T, vouts=[self.SPK_A], confirmations=0)
        self.core.mempool[self.T] = {"fees": {"base": 0.00001}, "ancestorcount": 1}
        self._hist(self.SPK_A)
        del self.core.wallet_txs[self.T]
        self._force_refresh()
        self.assertEqual(self._hist(self.SPK_A), [])

    def test_incremental_cursor_advances(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], confirmations=1,
                         blockheight=100)
        self._hist(self.SPK_A)
        self.core.lastblock = "tip1"
        self._force_refresh()
        self._hist(self.SPK_A)
        self._force_refresh()
        self._hist(self.SPK_A)
        cursors = [c[1] for c in self.core.method_calls("listsinceblock")]
        self.assertEqual(cursors, ["", "tip0", "tip1"])

    def test_decode_failure_does_not_advance_cursor(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], confirmations=1,
                         blockheight=100)
        real_call = self.core._call
        failures = {"n": 0}

        def flaky(method, *params):
            if method == "gettransaction" and failures["n"] == 0:
                failures["n"] += 1
                raise RPCError(-28, "Loading wallet…")
            return real_call(method, *params)

        self.core.rpc.call.side_effect = flaky
        self.assertEqual(self._hist(self.SPK_A), [])        # failed, retried later
        self._force_refresh()
        self.assertEqual(self._hist(self.SPK_A), [(self.P, 100, None)])
        cursors = [c[1] for c in self.core.method_calls("listsinceblock")]
        self.assertEqual(cursors, ["", ""])                 # cursor held back

    def test_height_from_confirmations_when_blockheight_missing(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], confirmations=6)   # no blockheight
        self.assertEqual(self._hist(self.SPK_A), [(self.P, 95, None)])

    def test_ttl_prevents_repeated_refresh(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], confirmations=1, blockheight=100)
        self._hist(self.SPK_A)
        self._hist(self.SPK_A)
        self.assertEqual(len(self.core.method_calls("listsinceblock")), 1)

    def test_refresh_error_resets_cursor(self):
        self.core.add_tx(self.P, vouts=[self.SPK_A], confirmations=1, blockheight=100)
        self._hist(self.SPK_A)
        self.assertEqual(self.idx._last_block, "tip0")
        real_call = self.core._call
        self.core.rpc.call.side_effect = lambda m, *p: (
            (_ for _ in ()).throw(RPCError(-5, "Block not found"))
            if m == "listsinceblock" else real_call(m, *p))
        self._force_refresh()
        self._hist(self.SPK_A)
        self.assertEqual(self.idx._last_block, "")

    def test_server_history_format_from_index(self):
        # _get_history orders confirmed entries by height then appends
        # mempool entries with their fee; entries without a fee are dropped.
        server = _make_server()
        server._wallet_index.history_for_spk = MagicMock(return_value=[
            ("c" * 64, 0, 1500),
            ("b" * 64, 120, None),
            ("a" * 64, 100, None),
            ("d" * 64, -1, None),       # no fee -> skipped
        ])
        self.assertEqual(server._get_history(spk_hex=self.SPK_A.upper()), [
            {"tx_hash": "a" * 64, "height": 100},
            {"tx_hash": "b" * 64, "height": 120},
            {"tx_hash": "c" * 64, "height": 0, "fee": 1500},
        ])
        server._wallet_index.history_for_spk.assert_called_once_with(self.SPK_A)


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
