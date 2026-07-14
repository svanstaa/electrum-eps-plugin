# Electrum Personal Server — Electrum Plugin

An Electrum plugin that reimplements [Electrum Personal Server](https://github.com/chris-belcher/electrum-personal-server)
functionality inline, letting you connect Electrum to your own Bitcoin
Core full node without running a separate process.

Tested against Electrum's `1.7` protocol branch (PyQt6) and Bitcoin
Core 30 on testnet4.

## What it does

When the plugin is enabled and configured, it:

1. Spawns a local TLS Electrum-protocol server on `127.0.0.1:50002`,
   answering wallet RPCs (`blockchain.scriptpubkey.*`,
   `blockchain.outpoint.subscribe`, `blockchain.transaction.*`, header
   subscriptions, broadcast, fee estimation, etc.) directly from your
   node. The server speaks **Electrum protocol 1.7 only**: clients send
   scriptPubKeys directly, so the server needs no knowledge of the
   wallet. (Protocol ≤ 1.6 queries by scripthash — a one-way hash that
   would require pre-registering wallet addresses — and is not
   supported; released Electrum ≤ 4.8 cannot connect.)
2. Makes Bitcoin Core watch your wallet's scripts **on demand**: as the
   wallet subscribes to scriptPubKeys, the plugin imports each one into
   Core. This works for arbitrary addresses, including multisig and
   hardware-wallet wallets, with no xpub required.
3. Optionally **bulk-imports** your wallet's descriptors and triggers a
   Core rescan, to surface *historical* transactions. Single-signature
   (`wpkh` / `sh(wpkh)` / `pkh`) and multisig (`wsh`/`sh(wsh)`/`sh` of
   `sortedmulti`) wallets are supported, via `importdescriptors`
   (Core ≥ 0.21) with `importmulti` fallback for single-sig.
4. Auto-configures Electrum to use the embedded server (`oneserver` plus
   a server bookmark), so Electrum never talks to any third-party server.

## Repository layout

```
electrum-eps-plugin/
├── eps/                    Plugin package — distributed as eps-X.Y.Z.zip
│   ├── manifest.json       Plugin metadata
│   ├── __init__.py         Config key declarations
│   ├── qt.py               BasePlugin subclass, settings UI, server lifecycle
│   ├── rpc.py              Synchronous Core JSON-RPC client + cookie auth
│   ├── addresses.py        Descriptor building, on-demand ScriptWatcher, bulk import
│   ├── server.py           Electrum protocol TCP+TLS server
│   └── tls.py              Self-signed certificate generation
├── tests/                  unittest suite (no Electrum install required)
└── .github/workflows/
    └── release.yml         Builds eps-X.Y.Z.zip on tag push
```

### Threading model

| Thread                  | Purpose                                                  |
| ----------------------- | -------------------------------------------------------- |
| Main Qt thread          | GUI, config reads/writes                                 |
| `eps-server-main`       | `socket.accept()` loop                                   |
| `eps-client-<peer>`     | One per connected Electrum client                        |
| `eps-notifier`          | Polls Core every 10 s; pushes header + script-status pushes |
| `ImportWorker` (QThread)| Bulk address import + rescan, reports progress to Qt     |

All Bitcoin Core RPC calls are synchronous (blocking). Each client has
its own thread; EPS is single-user by design. Status updates from
background threads to the GUI are marshalled through a Qt signal
(`_StatusBridge`) so GUI widgets are only ever touched on the Qt thread.

## Bitcoin Core setup

The plugin needs RPC access to a Bitcoin Core node and a dedicated
watch-only descriptor wallet to import addresses into.

### Authentication

Either method works (configured in **Wallet → EPS Settings**):

- **Static credentials** — set them in `bitcoin.conf` and enter them in
  the **RPC Auth** field as `user:password`:

  ```
  server=1
  rpcuser=eps
  rpcpassword=eps          # use something secure outside testing
  ```

- **Cookie auth** — leave **RPC Auth** blank and set the **Directory**
  field to your Core datadir; the plugin reads `<datadir>/<network>/.cookie`.

  Note: if `rpcuser`/`rpcpassword` are present in `bitcoin.conf`, Core
  does **not** write a `.cookie` file, so cookie auth is unavailable —
  use the static credentials in that case. The cookie is also only
  readable by the user Core runs as.

### Watch-only wallet (Bitcoin Core ≥ 25)

```bash
bitcoin-cli -testnet4 createwallet eps-test true true "" false true true
#                                           ^disable_private_keys
#                                                ^blank
#                                                    ^passphrase
#                                                       ^avoid_reuse
#                                                             ^descriptors
#                                                                  ^load_on_startup
```

Enter this wallet's name in the **Wallet** field. The plugin imports
into it on demand (protocol 1.7) and when you click **Import &
rescan**. Expect the first rescan to take minutes (testnet4)
to hours (mainnet; pruned nodes are supported but only scan non-pruned
history).

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

1. Open **Wallet → EPS Settings** and enter your Bitcoin Core RPC URL,
   authentication (RPC Auth *or* a datadir for cookie auth), and the
   watch-only wallet name.
2. Click **Save & Connect**. The plugin starts the embedded server and
   automatically points Electrum at `127.0.0.1:50002`.
3. (First time per wallet, optional) Set the **Wallet birth date** —
   the earliest possible first use of the wallet — then click
   **Import & rescan** to bulk-import descriptors and rescan for
   historical transactions. The rescan starts at the birth date's
   block height, so a recent date turns hours (mainnet, full scan) into
   minutes. Clicking again re-runs the rescan (e.g. after changing the
   birth date). New activity is picked up automatically without this.
4. On subsequent wallet opens the server starts automatically (when RPC
   is configured).

The status label in the settings dialog reports connection state and the
embedded server's address.

## Limitations / TODO

- **Historical sync still needs the bulk import + rescan.** On-demand
  (1.7) watching imports scripts with `timestamp: now`, so it only
  guarantees *future* activity; past transactions appear after the
  bulk-import rescan (bounded by the wallet birth date). A debounced
  automatic rescan after on-demand imports — making the xpub bulk
  import fully optional — is planned.
- History lookup is `O(mempool size)` per `get_history` call. Fine at
  personal-server scale; a per-address incremental index would scale
  better on a busy mainnet node.
- Requires a protocol 1.7 client (Electrum's `protocol_1.7` branch, or
  any release that ships 1.7). Released Electrum ≤ 4.8 speaks 1.4–1.6
  only and cannot connect.
- One Electrum client at a time is the design assumption (multiple work,
  but there is no per-client deduplication of work).
- Lightning is not supported.

## Running tests

```bash
python3 -m unittest discover -s tests -v
```

or, if you prefer pytest:

```bash
pip install pytest && pytest tests/
```

Tests stub the `electrum` package, so you don't need an Electrum
checkout to run them.

## License

MIT — see [LICENSE](./LICENSE).
