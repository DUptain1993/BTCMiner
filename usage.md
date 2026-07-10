# ⚡ BTCMiner (GUI + Retro CLI Edition) - Usage Guide

An advanced, multithreaded multi-chain Bitcoin and Cryptocurrency wallet generator, hunter, and balance checker. The tool features a high-performance backend, proxy rotation, multiple derivation methods, a GUI, and the classic LizardX2 retro CLI console.

---

## 📋 Requirements & Dependencies

Before running the tool, make sure you have Python 3 installed along with the required libraries:

```bash
pip install requests ecdsa base58 colorama rich
```

- **`requests`**: For querying REST blockchain APIs.
- **`ecdsa`**: For cryptographic key generation (SECP256k1 curve).
- **`base58`**: For legacy and Segwit address formatting.
- **`colorama`**: For retro-themed console styling.
- **`rich`** *(Optional)*: For enhanced statistics visualization in the console.

---

## 🚀 Running the Tool

You can start the tool in either **GUI** or **CLI** mode:

### 1. GUI Mode (Graphical Interface)
To launch the graphical window directly:
```bash
python3 btcminer.py --gui
```
*Note: If no arguments are passed and a desktop environment is active, the script will automatically attempt to open the GUI.*

### 2. CLI Mode (Command Line Interface)
To force CLI mode:
```bash
python3 btcminer.py --cli
```
*Note: If running in a headless server environment (no active display), the script will automatically fallback to CLI mode.*

---

## 🛠️ Configuration (`config.json`)

The tool reads its initial settings from `config.json`. If it does not exist, a default version will be auto-generated at startup:

```json
{
    "settings": {
        "checker": {
            "filename": "check.txt"
        },
        "bruteforcer": {
            "strenght": 128,
            "language": "english",
            "passphere": "None"
        },
        "general": { 
            "failed": "failed.txt",
            "success": "success.txt",
            "addresstype" : "p2pkh"
        }
    }
}
```

### Key Parameters:
- **`strenght`**: Entropy strength for BIP39 mnemonic generation. Options:
  - `128` (Generates 12 words)
  - `160` (Generates 15 words)
  - `192` (Generates 18 words)
  - `224` (Generates 21 words)
  - `256` (Generates 24 words)
- **`language`**: BIP39 language format (e.g. `english`, `spanish`, `french`, `japanese`, etc.).
- **`passphere`**: Optional passphrase attached to the seed. Set to `"None"` to ignore.
- **`addresstype`**: Derivation address format for BTC:
  - `p2pkh` (Legacy address starting with `1`)
  - `p2sh` (SegWit address starting with `3`)
  - `p2wpkh` (Native SegWit Bech32 starting with `bc1`)

---

## 🎮 CLI Modes & Interactive Menu

When starting in CLI mode, you will be presented with the retro colored logo and a menu selection:

```text
Make a choice between Checker, Bruteforcer, and GUI [C] - [B] - [G] >
```

### Choice `[C] - Checker`
Generates BIP39 mnemonics dynamically using the wordlist and performs multithreaded checks. *(No longer requires reading from `check.txt`)*

### Choice `[B] - Bruteforcer`
Runs the continuous bruteforcing loop to generate and test random seeds against the network.

### Choice `[G] - GUI`
Launches the Tkinter application panel.

---

## 🎨 GUI Mode Options

The graphical panel provides fine-grained controls:

1. **Method Selector**: Support for different generation styles:
   - `bip39`: Standard BIP39 mnemonics.
   - `brain`: Passphrase hashing to key.
   - `raw`: Random private key.
   - `satoshi`: Legacy uncompressed/compressed key formats.
   - `mini`: Mini private key formats (`S...`).
   - `vanity`: Search for custom address prefixes.
2. **Chain Checkboxes**: Enable/disable checking on **BTC**, **LTC**, **ETH**, or **DOGE**.
3. **Threads**: Spin up to `512` concurrent threads to maximize bandwidth usage.
4. **Proxy File**: Load `http`, `https`, `socks4`, or `socks5` proxies to distribute network queries and prevent API rate-limiting.
5. **Webhook URL**: Connect to a Discord or custom server to notify you instantly when a wallet with a balance or active transaction history is discovered.
6. **Mnemonic Checker**: Paste a single mnemonic to verify its addresses and balances manually.

---

## 📁 Output & Log Files

The tool generates records for its outputs:

### In CLI Mode:
- **`success.txt`**: Logs details of wallets found to contain a balance or transaction activity.
- **`failed.txt`**: Logs failed seeds that checked empty.
*Format:* `address | balance | received | seed | private_key | entropy | wif`

### In GUI Mode:
- **`found_wallets/found_*.jsonl`**: Detailed JSON lines files containing full cryptographic details of successful/active wallets.

---

## ⚠️ Important Precautions & Performance Tuning

1. **API Rate Limiting**: The public web APIs (Blockcypher, Blockchain.com) enforce strict request limit policies. To prevent timeouts:
   - Keep the worker thread count at a reasonable value (e.g. `8` to `32`) if not using proxies.
   - Load a proxy list (`proxy.txt`) formatted as `IP:PORT` or `USER:PASS@IP:PORT` to spread queries across multiple IP addresses.
2. **Electrum SSL**: By default, BTC and LTC checks query official Electrum servers via SSL sockets. This is highly efficient and operates at near zero cost/limit.
3. **Safety**: Never share your `success.txt` or `found_wallets` folders. They contain raw unencrypted private keys and WIFs of generated addresses.
