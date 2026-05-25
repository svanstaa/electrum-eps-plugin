# Electrum Personal Server — Electrum Plugin

An Electrum plugin that reimplements [Electrum Personal Server](https://github.com/chris-belcher/electrum-personal-server)
functionality inline, letting you connect Electrum to your own Bitcoin
Core full node without running a separate process.

Tested against Electrum 4.7.2 (AppImage, PyQt6) and Bitcoin Core 30 on
testnet4 and mainnet.

## What it does

When the plugin is enabled and the embedded server is started, it:

1. Reads the xpub of your currently-open Electrum wallet.
2. Imports the corresponding receive + change descriptors into Bitcoin
   Core as a watch-only wallet (using `importdescriptors` with a default
   range of 1000 addresses per branch).
3. Spawns a local TLS Electrum-protocol server on `127.0.0.1:60002` that
   answers all wallet-level RPCs (`blockchain.scripthash.*`,
   `blockchain.transaction.*`, header subscriptions, broadcast, etc.)
   directly from your node.
4. Bookmarks itself in Electrum's Network preferences so you can
   `Manual server selection` → choose `127.0.0.1:60002`.

The result: Electrum never talks to any third-party server. Privacy and
verification come from your own full node.

## Repository layout

```
electrum-eps-plugin/
├── eps/                    Plugin package — distributed as eps-X.Y.Z.zip
│   ├── manifest.json       Plugin metadata
│   ├── __init__.py         Config key declarations
│   ├── qt.py               BasePlugin subclass, settings UI, server lifecycle
│   ├── rpc.py              Synchronous Bitcoin Core JSON-RPC 2.0 client
│   ├── addresses.py        BIP32 derivation + importdescriptors/importmulti
│   ├── server.py           Electrum protocol TCP+TLS server
│   └── tls.py              Self-signed certificate generation
├── tests/                  pytest unit tests (no Electrum dependency required)
└── .github/workflows/
    └── release.yml         Builds eps-X.Y.Z.zip on tag push
```

### Threading model

| Thread                  | Purpose                                            |
| ----------------------- | -------------------------------------------------- |
| Main Qt thread          | GUI, config reads/writes                           |
| `eps-server-main`       | `socket.accept()` loop                             |
| `eps-client-<peer>`     | One per connected Electrum client                  |
| `eps-notifier`          | Polls Core every 10 s, pushes header notifications |
| `ImportWorker` (QThread)| Address import + rescan, reports progress to Qt    |

All Bitcoin Core RPC calls are synchronous (blocking). Each client has
its own thread; EPS is single-user by design. Status updates from
background threads to the GUI are marshalled through a Qt signal
(`_StatusBridge`) so the GUI label is only ever touched on the Qt thread.

## Bitcoin Core setup

`bitcoin.conf`:
```
server=1
rpcuser=eps
rpcpassword=eps          # use something secure outside testing

```

Create a dedicated watch-only descriptor wallet (Bitcoin Core ≥ 25):
```bash
bitcoin-cli -testnet4 createwallet eps-test true true "" false true true
#                                           ^disable_private_keys
#                                                ^blank
#                                                    ^passphrase
#                                                       ^avoid_reuse
#                                                             ^descriptors
#                                                                  ^load_on_startup
```

The plugin will populate this wallet via `importdescriptors` when you
click **Import addresses from open wallet**. Expect the first rescan to
take minutes (testnet4) to hours (mainnet, pruned ok).

## Installing the plugin (end users)

1. Download `eps-X.Y.Z.zip` from the [GitHub releases](#) page.
2. In Electrum: **Tools → Plugins → Add** → select the zip.
3. Authorize with your Electrum plugin password (set on first use).
4. Restart Electrum; **EPS Settings** now appears in the **Wallet** menu.

## Installing the plugin (developers)

Electrum's external plugin manager loads `.zip` files from the
network-specific plugin directory. Symlinks and bare directories there
are **ignored** by the loader.

```bash
git clone <this repo> ~/repos/electrum-eps-plugin
cd ~/repos/electrum-eps-plugin

# Build and install for testnet4
zip -r eps-0.1.0.zip eps/
cp eps-0.1.0.zip ~/.electrum/testnet4/plugins/

# Restart Electrum and re-authorize (the zip hash changes every build)
~/Downloads/electrum-4.7.2-x86_64.AppImage --testnet4
```

A one-liner for the inner dev loop:
```bash
cd ~/repos/electrum-eps-plugin && \
    rm -f eps-0.1.0.zip && rm -rf eps/__pycache__ && \
    zip -r eps-0.1.0.zip eps/ > /dev/null && \
    cp eps-0.1.0.zip ~/.electrum/testnet4/plugins/
```

## Usage flow

1. Configure Bitcoin Core RPC credentials in **Wallet → EPS Settings**.
2. Click **Import addresses from open wallet** (first time only per
   wallet; subsequent opens are instant).
3. Click **Start**.
4. **Network → Manual server selection → `127.0.0.1:60002`**.

The status label in the settings dialog turns green when an Electrum
client connects.

## Limitations / TODO

- History lookup is `O(mempool size)` per `blockchain.scripthash.get_history`
  call. Acceptable on a personal-server scale, but a per-address
  incremental mempool index updated by the notifier thread would scale
  better on mainnet.
- No push notifications on `blockchain.scripthash.subscribe`: when a
  new mempool tx arrives, Electrum only learns about it on the next
  block header notification (every ~10 s) or on user-triggered refresh.
- Only one Electrum client at a time is the design assumption (multiple
  clients work, but no per-client deduplication of work).
- Lightning is not supported.

## Running tests

```bash
pip install pytest
pytest tests/
```

Tests mock the `electrum` package, so you don't need an Electrum
checkout to run them.

## License

MIT — see [LICENSE](./LICENSE).
