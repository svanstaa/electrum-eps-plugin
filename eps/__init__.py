# eps/__init__.py
#
# Config keys used by this plugin (all prefixed 'eps_'):
#   eps_rpc_host        – Bitcoin Core RPC host (default: 127.0.0.1)
#   eps_rpc_port        – Bitcoin Core RPC port (default: 8332)
#   eps_rpc_user        – RPC username
#   eps_rpc_pass        – RPC password
#   eps_rpc_wallet      – optional named Core wallet (default: '')
#   eps_rpc_datadir     – Bitcoin Core datadir (cookie auth; optional)
#   eps_listen_host     – host to bind our Electrum server on (default: 127.0.0.1)
#   eps_listen_port     – port to bind our Electrum server on (default: 50002)
#   eps_gap_limit       – how many addresses beyond last used to import (default: 20)
#   eps_autostart       – start server automatically when plugin is enabled (default: False)
#   eps_cert_path       – path to TLS certificate file (PEM)
#   eps_key_path        – path to TLS private key file (PEM)
