"""
Tests for eps.rpc — the synchronous Bitcoin Core JSON-RPC wrapper.
All HTTP is mocked; no real node required.
"""
import json
import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eps.rpc import BitcoinRPC, RPCError


def _mock_response(result=None, error=None, status=200):
    """Return a mock that urllib.request.urlopen will yield."""
    body = {"id": 1, "result": result, "error": error}
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(body).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestBitcoinRPC(unittest.TestCase):

    def setUp(self):
        self.rpc = BitcoinRPC("127.0.0.1", 8332, "user", "pass")

    @patch("urllib.request.urlopen")
    def test_call_success(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(result=42)
        result = self.rpc.call("getblockcount")
        self.assertEqual(result, 42)

    @patch("urllib.request.urlopen")
    def test_call_rpc_error(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            error={"code": -5, "message": "No such mempool or blockchain transaction"})
        with self.assertRaises(RPCError) as ctx:
            self.rpc.call("getrawtransaction", "deadbeef")
        self.assertEqual(ctx.exception.code, -5)

    @patch("urllib.request.urlopen")
    def test_getblockcount(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(result=850000)
        self.assertEqual(self.rpc.getblockcount(), 850000)

    @patch("urllib.request.urlopen")
    def test_wallet_url(self, mock_urlopen):
        rpc = BitcoinRPC("127.0.0.1", 8332, "u", "p", wallet="eps")
        mock_urlopen.return_value = _mock_response(result={})
        rpc.getwalletinfo()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertIn("/wallet/eps", req.full_url)

    @patch("urllib.request.urlopen")
    def test_listunspent_no_address_filter(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(result=[])
        self.rpc.listunspent(0, 9999999)
        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual(body["params"], [0, 9999999])

    @patch("urllib.request.urlopen")
    def test_listunspent_with_address_filter(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(result=[])
        self.rpc.listunspent(1, 9999999, ["bc1qtest"])
        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual(body["params"], [1, 9999999, ["bc1qtest"]])


if __name__ == "__main__":
    unittest.main()
