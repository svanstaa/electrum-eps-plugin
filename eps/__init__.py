# eps/__init__.py
#
# Config keys used by this plugin (all prefixed 'eps_'):
#   eps_rpc_host        – Bitcoin Core RPC host (default: 127.0.0.1)
#   eps_rpc_port        – Bitcoin Core RPC port (default: 8332)
#   eps_rpc_user        – RPC username
#   eps_rpc_pass        – RPC password
#   eps_rpc_wallet      – optional named Core wallet (default: '')
#   eps_rpc_datadir     – Bitcoin Core datadir (cookie auth; optional)
#   eps_birth_date      – wallet birth date 'YYYY-MM-DD'; bounds the import
#                         rescan (default: '' = scan whole chain)
#
# The EPS server always binds 127.0.0.1:50002 (see EPS_LISTEN_* in eps/qt.py);
# the plugin auto-wires Electrum to it, so it is not user-configurable.
#
# TLS: a self-signed certificate is auto-generated on first start and stored under
# the Electrum data directory (see eps/tls.py); no user configuration required.
