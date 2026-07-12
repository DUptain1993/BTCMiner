#!/usr/bin/env python3
"""
 ▄▄   ▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   ▄▄▄ ▄▄▄▄▄▄▄ 
█  █▄█  █  █ █  █       █       █       █   ▄  █ █   █       █
█       █  █▄█  █  ▄▄▄▄▄█▄     ▄█    ▄▄▄█  █ █ █ █   █   ▄   █
█       █       █ █▄▄▄▄▄  █   █ █   █▄▄▄█   █▄▄█▄█   █  █ █  █
█       █▄     ▄█▄▄▄▄▄  █ █   █ █    ▄▄▄█    ▄▄  █   █       █
█ ██▄██ █ █   █  ▄▄▄▄▄█ █ █▄▄▄█ █   █▄▄▄█   █  █ █   █       █
█▄█   █▄█ █▄▄▄█ █▄▄▄▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄█  █▄█▄▄▄█▄▄▄▄▄▄▄█

Multi-Chain Wallet Hunter & Checker (GUI + Retro CLI Edition)
Author: LizardX2 & Mysterio
"""

import os
import sys
import json
import time
import hmac
import random
import socket
import ssl
import secrets
import logging
import argparse
import threading
import traceback
import hashlib
import queue
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    tk = None
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Optional, List, Dict, Tuple, Callable, Any

# ─── Colorama & Retro CLI Styling ──────────────────────────────────────────
try:
    from colorama import Fore, init
    init()
except ImportError:
    class MockFore:
        RED = GREEN = BLUE = YELLOW = RESET = LIGHTYELLOW_EX = LIGHTRED_EX = LIGHTBLACK_EX = LIGHTGREEN_EX = LIGHTWHITE_EX = ""
    Fore = MockFore()

# ─── Third-Party Dependencies ───────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Missing 'requests' — pip install requests")
    sys.exit(1)

try:
    import ecdsa
    from ecdsa import SECP256k1, SigningKey, VerifyingKey
except ImportError:
    print("Missing 'ecdsa' — pip install ecdsa")
    sys.exit(1)

try:
    import base58
except ImportError:
    print("Missing 'base58' — pip install base58")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

# ─── Global Configuration & Files ───────────────────────────────────────────
CONFIG_FILE = 'config.json'
config_failed = "failed.txt"
config_success = "success.txt"
c_config_file = "check.txt"
b_config_strenght = 128
b_config_language = "english"
b_config_passphere = "None"
config_address = "p2pkh"

api_url = "https://chain.api.btc.com/v3/address"
api_get_data = "data"
api_get_balance = "balance"
api_get_recieved = "received"

# Safety Locks
print_lock = threading.Lock()
file_lock = threading.Lock()

# Load original configuration if present
if os.path.isfile(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            data = json.load(f)
            b_config_strenght = data["settings"]["bruteforcer"]["strenght"]
            b_config_language = data["settings"]["bruteforcer"]["language"]
            b_config_passphere = data["settings"]["bruteforcer"]["passphere"]
            c_config_file = data["settings"]["checker"]["filename"]
            config_failed = data["settings"]["general"]["failed"]
            config_success = data["settings"]["general"]["success"]
            config_address = data["settings"]["general"]["addresstype"]
            api_url = data["settings"]["general"]["api"]["api_url"]
            api_get_data = data["settings"]["general"]["api"]["api_get_data"]
            api_get_balance = data["settings"]["general"]["api"]["api_get_balance"]
            api_get_recieved = data["settings"]["general"]["api"]["api_get_recieved"]
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading config.json: {e}. Using defaults.{Fore.RESET}")
else:
    # Auto-create default config.json for convenience
    default_config = {
        "settings": {
            "checker": {
                "filename": "check.txt"
            },
            "bruteforcer": {
                "STRENGHT_OPTIONS": "128, 160, 228, 192, 224, 256",
                "strenght": 128,
                "LANGUAGE_OPTIONS": "english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese, korean",
                "language": "english",
                "passphere": "None"
            },
            "general": { 
                "failed": "failed.txt",
                "success": "success.txt",
                "ADDRESS_OPTIONS": "p2pkh, p2sh, p2wpkh, p2wpkh_in_p2sh, p2wsh, p2wsh_in_p2sh",
                "addresstype" : "p2pkh",
                "api": {
                    "api_url": "https://chain.api.btc.com/v3/address",
                    "api_get_data": "data",
                    "api_get_balance": "balance",
                    "api_get_recieved": "received"
                }
            }
        }
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=4)
    except Exception:
        pass

# Ensure success/failed output files exist
for filepath in [config_failed, config_success]:
    if not os.path.exists(filepath):
        try:
            with open(filepath, 'w') as f:
                pass
        except Exception:
            pass

# ─── Constants ──────────────────────────────────────────────────────────────

BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
BIP39_WORDLIST_FILE = "bip39_wordlist.txt"

CHAIN_CONFIG = {
    "BTC": {
        "derivation_paths": {
            "legacy":      "m/44'/0'/0'/0/0",
            "segwit":      "m/49'/0'/0'/0/0",
            "bech32":      "m/84'/0'/0'/0/0",
        },
        "p2pkh_version":  b'\x00',
        "p2sh_version":   b'\x05',
        "bech32_hrp":     "bc",
        "wif_prefix":     b'\x80',
        "api_endpoints": [
            {"name": "blockchain.info", "url": "https://blockchain.info/balance?active={address}", "parser": "blockchain_info", "rate_limit_ms": 500},
            {"name": "blockcypher", "url": "https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance", "parser": "blockcypher", "rate_limit_ms": 300},
            {"name": "mempool.space", "url": "https://mempool.space/api/address/{address}", "parser": "mempool_space", "rate_limit_ms": 250},
        ],
    },
    "LTC": {
        "derivation_paths": {
            "legacy":  "m/44'/2'/0'/0/0",
            "segwit":  "m/49'/2'/0'/0/0",
            "bech32":  "m/84'/2'/0'/0/0",
        },
        "p2pkh_version":  b'\x30',
        "p2sh_version":   b'\x32',
        "bech32_hrp":     "ltc",
        "wif_prefix":     b'\xb0',
        "api_endpoints": [
            {"name": "blockcypher_ltc", "url": "https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance", "parser": "blockcypher", "rate_limit_ms": 300},
            {"name": "ltc_explorer", "url": "https://litecoinblockexplorer.net/api/v2/address/{address}", "parser": "ltc_explorer", "rate_limit_ms": 400},
        ],
    },
    "ETH": {
        "derivation_paths": {"legacy": "m/44'/60'/0'/0/0"},
        "p2pkh_version":  None,
        "p2sh_version":   None,
        "bech32_hrp":     None,
        "wif_prefix":     None,
        "api_endpoints": [
            {"name": "etherscan", "url": "https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest", "parser": "etherscan", "rate_limit_ms": 250},
            {"name": "blockcypher_eth", "url": "https://api.blockcypher.com/v1/eth/main/addrs/{address}/balance", "parser": "blockcypher_eth", "rate_limit_ms": 300},
            {"name": "ethplorer", "url": "https://api.ethplorer.io/getAddressInfo/{address}", "parser": "ethplorer", "rate_limit_ms": 500},
        ],
    },
    "DOGE": {
        "derivation_paths": {"legacy": "m/44'/3'/0'/0/0"},
        "p2pkh_version":  b'\x1e',
        "p2sh_version":   b'\x16',
        "bech32_hrp":     None,
        "wif_prefix":     b'\x9e',
        "api_endpoints": [
            {"name": "blockcypher_doge", "url": "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance", "parser": "blockcypher", "rate_limit_ms": 300},
        ],
    },
}

ELECTRUM_SERVERS = {
    "BTC": [
        {"host": "electrum.blockchain.info", "port": 50002, "ssl": True},
        {"host": "electrum.bitaroo.net", "port": 50002, "ssl": True},
        {"host": "electrum.emzy.de", "port": 50002, "ssl": True},
        {"host": "fortress.qtornado.com", "port": 50002, "ssl": True},
        {"host": "electrum.acinq.co", "port": 50002, "ssl": True},
        {"host": "electrum.coinucopia.io", "port": 50002, "ssl": True},
        {"host": "alexvpetrov.com", "port": 50002, "ssl": True},
        {"host": "electrum3.goldenlearner.com", "port": 50002, "ssl": True},
        {"host": "electrum.diynodes.com", "port": 50002, "ssl": True},
        {"host": "electrum.kendigs.net", "port": 50002, "ssl": True},
        {"host": "electrum.hsmiths.com", "port": 50002, "ssl": True},
        {"host": "e2.criptointercambio.com.br", "port": 50002, "ssl": True},
    ],
    "LTC": [
        {"host": "electrum-ltc.wildon.party", "port": 50002, "ssl": True},
        {"host": "electrum-ltc.ddns.net", "port": 50002, "ssl": True},
        {"host": "backup.electrum-ltc.org", "port": 50002, "ssl": True},
        {"host": "electrum.ltc.xurious.com", "port": 50002, "ssl": True},
    ],
}

ETH_RPC_ENDPOINTS = [
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://cloudflare-eth.com",
    "https://ethereum.publicnode.com",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
    "https://rpc.flashbots.net",
]

GEN_METHODS = {
    "bip39":         "Standard BIP39 12-word mnemonic + BIP32 derivation",
    "brain":         "Brain wallet: SHA256(passphrase) → private key (old school)",
    "raw":           "Raw random 256-bit private key (Type-0, pre-BIP32)",
    "satoshi":       "Satoshi-era: Raw key → compressed + uncompressed addresses",
    "mini":          "Mini private key format (S... — Satoshi Dice era)",
    "uncompressed":  "Legacy uncompressed public key address (original Bitcoin format)",
    "vanity":        "Vanity prefix search (generates until prefix matches)",
}

# ─── BIP39 Wordlist Management ──────────────────────────────────────────────

class BIP39Wordlist:
    _wordlist: Optional[List[str]] = None
    _lock = threading.Lock()

    @classmethod
    def load(cls) -> List[str]:
        if cls._wordlist is not None:
            return cls._wordlist

        with cls._lock:
            if cls._wordlist is not None:
                return cls._wordlist

            if os.path.exists(BIP39_WORDLIST_FILE):
                with open(BIP39_WORDLIST_FILE, 'r') as f:
                    words = [w.strip() for w in f.readlines() if w.strip()]
                if len(words) == 2048:
                    cls._wordlist = words
                    return words

            print(f"[*] Downloading BIP39 wordlist from GitHub...")
            try:
                response = requests.get(BIP39_WORDLIST_URL, timeout=30)
                response.raise_for_status()
                words = response.text.strip().split('\n')
                words = [w.strip() for w in words if w.strip()]

                if len(words) != 2048:
                    raise ValueError(f"Wordlist has {len(words)} words, expected 2048")

                with open(BIP39_WORDLIST_FILE, 'w') as f:
                    f.write('\n'.join(words))

                cls._wordlist = words
                print(f"[+] BIP39 wordlist loaded ({len(words)} words)")
                return words
            except Exception as e:
                print(f"[!] Failed to download wordlist: {e}")
                print("[*] Falling back to embedded mini-wordlist (demo only)")
                cls._wordlist = cls._embedded_fallback()
                return cls._wordlist

    @staticmethod
    def _embedded_fallback() -> List[str]:
        sample = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
            "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        ]
        while len(sample) < 256:
            sample.append(f"word{len(sample)}")
        return sample

    @classmethod
    def get_entropy_bytes(cls, strength: int = 128) -> bytes:
        return secrets.token_bytes(strength // 8)

    @classmethod
    def entropy_to_mnemonic(cls, entropy: bytes) -> List[str]:
        words = cls.load()
        entropy_bits = len(entropy) * 8
        checksum_bits = entropy_bits // 32
        total_bits = entropy_bits + checksum_bits

        entropy_int = int.from_bytes(entropy, 'big')
        entropy_bits_str = bin(entropy_int)[2:].zfill(entropy_bits)

        checksum_hash = hashlib.sha256(entropy).digest()
        checksum_int = int.from_bytes(checksum_hash, 'big')
        checksum_bits_str = bin(checksum_int)[2:].zfill(256)[:checksum_bits]

        all_bits = entropy_bits_str + checksum_bits_str

        mnemonic = []
        for i in range(0, total_bits, 11):
            index = int(all_bits[i:i+11], 2)
            mnemonic.append(words[index % len(words)])

        return mnemonic

    @classmethod
    def generate_mnemonic_with_strength_and_entropy(cls, strength: int = 128, language: str = "english") -> Tuple[List[str], str]:
        # Try to use hdwallet if installed
        try:
            from hdwallet.utils import generate_mnemonic as hd_gen
            mnemonic_str = hd_gen(language=language, strength=strength)
            # Mock entropy calculation or compute
            entropy_hex = hashlib.sha256(mnemonic_str.encode()).hexdigest()[:strength // 4]
            return mnemonic_str.split(), entropy_hex
        except Exception:
            pass

        entropy = cls.get_entropy_bytes(strength)
        mnemonic = cls.entropy_to_mnemonic(entropy)
        return mnemonic, entropy.hex()

    @classmethod
    def generate_mnemonic(cls, word_count: int = 12) -> List[str]:
        strength = 128 if word_count == 12 else 256
        entropy = cls.get_entropy_bytes(strength)
        return cls.entropy_to_mnemonic(entropy)

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: List[str], passphrase: str = "") -> bytes:
        if passphrase == "None":
            passphrase = ""
        mnemonic_str = " ".join(mnemonic)
        salt = ("mnemonic" + passphrase).encode('utf-8')
        seed = hashlib.pbkdf2_hmac('sha512', mnemonic_str.encode('utf-8'), salt, 2048, dklen=64)
        return seed

# ─── BIP32 Key Derivation ───────────────────────────────────────────────────

class BIP32Derivation:
    SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    @staticmethod
    def master_key_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return I[:32], I[32:]

    @classmethod
    def derive_child_key(cls, parent_key: bytes, parent_chain_code: bytes, index: int) -> Tuple[bytes, bytes]:
        hardened = index >= 0x80000000

        if hardened:
            data = b'\x00' + parent_key + index.to_bytes(4, 'big')
        else:
            parent_pubkey = cls.private_to_public_key(parent_key)
            data = parent_pubkey + index.to_bytes(4, 'big')

        I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        child_key_int = int.from_bytes(I[:32], 'big')
        child_chain_code = I[32:]

        parent_key_int = int.from_bytes(parent_key, 'big')
        child_key_int = (child_key_int + parent_key_int) % cls.SECP256K1_ORDER

        return child_key_int.to_bytes(32, 'big'), child_chain_code

    @classmethod
    def derive_path(cls, master_key: bytes, master_chain_code: bytes, path: str) -> Tuple[bytes, bytes]:
        if path in ('m', 'M', ''):
            return master_key, master_chain_code

        parts = path.strip().lower().lstrip('m/').split('/')
        key, chain_code = master_key, master_chain_code

        for part in parts:
            part = part.strip()
            if not part:
                continue
            if part.endswith("'") or part.endswith("h"):
                index = int(part.rstrip("'h")) + 0x80000000
            else:
                index = int(part)
            key, chain_code = cls.derive_child_key(key, chain_code, index)

        return key, chain_code

    @staticmethod
    def private_to_public_key(private_key: bytes, compressed: bool = True) -> bytes:
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()

        if compressed:
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            return prefix + x.to_bytes(32, 'big')
        else:
            return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

# ─── Address Generation ──────────────────────────────────────────────────────

class AddressGenerator:
    @staticmethod
    def ripemd160(data: bytes) -> bytes:
        try:
            h = hashlib.new('ripemd160')
            h.update(data)
            return h.digest()
        except ValueError:
            return AddressGenerator._ripemd160_fallback(data)

    @staticmethod
    def _ripemd160_fallback(message: bytes) -> bytes:
        h0 = 0x67452301
        h1 = 0xefcdab89
        h2 = 0x98badcfe
        h3 = 0x10325476
        h4 = 0xc3d2e1f0

        def f(x, y, z): return x ^ y ^ z
        def g(x, y, z): return (x & y) | (~x & z)
        def h(x, y, z): return (x | ~y) ^ z
        def i(x, y, z): return (x & z) | (y & ~z)
        def j(x, y, z): return x ^ (y | ~z)

        KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
        KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]

        rL = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
        ]
        rR = [
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
        ]

        sL = [
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
        ]
        sR = [
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
        ]

        import struct
        bit_len = len(message) * 8
        message += b'\x80'
        while (len(message) + 8) % 64 != 0:
            message += b'\x00'
        message += struct.pack('<Q', bit_len)

        for offset in range(0, len(message), 64):
            block = message[offset:offset+64]
            X = list(struct.unpack('<16I', block))

            AL, BL, CL, DL, EL = h0, h1, h2, h3, h4
            AR, BR, CR, DR, ER = h0, h1, h2, h3, h4

            for j_step in range(80):
                if j_step < 16:
                    T = (AL + f(BL, CL, DL) + X[rL[j_step]] + KL[0]) & 0xffffffff
                elif j_step < 32:
                    T = (AL + g(BL, CL, DL) + X[rL[j_step]] + KL[1]) & 0xffffffff
                elif j_step < 48:
                    T = (AL + h(BL, CL, DL) + X[rL[j_step]] + KL[2]) & 0xffffffff
                elif j_step < 64:
                    T = (AL + i(BL, CL, DL) + X[rL[j_step]] + KL[3]) & 0xffffffff
                else:
                    T = (AL + j(BL, CL, DL) + X[rL[j_step]] + KL[4]) & 0xffffffff
                shift = sL[j_step]
                T = ((T << shift) | (T >> (32 - shift))) & 0xffffffff
                T = (T + EL) & 0xffffffff
                AL, BL, CL, DL, EL = EL, T, BL, ((CL << 10) | (CL >> 22)) & 0xffffffff, DL

                if j_step < 16:
                    T = (AR + j(BR, CR, DR) + X[rR[j_step]] + KR[0]) & 0xffffffff
                elif j_step < 32:
                    T = (AR + i(BR, CR, DR) + X[rR[j_step]] + KR[1]) & 0xffffffff
                elif j_step < 48:
                    T = (AR + h(BR, CR, DR) + X[rR[j_step]] + KR[2]) & 0xffffffff
                elif j_step < 64:
                    T = (AR + g(BR, CR, DR) + X[rR[j_step]] + KR[3]) & 0xffffffff
                else:
                    T = (AR + f(BR, CR, DR) + X[rR[j_step]] + KR[4]) & 0xffffffff
                shift = sR[j_step]
                T = ((T << shift) | (T >> (32 - shift))) & 0xffffffff
                T = (T + ER) & 0xffffffff
                AR, BR, CR, DR, ER = ER, T, BR, ((CR << 10) | (CR >> 22)) & 0xffffffff, DR

            h0, h1, h2, h3, h4 = (
                (h1 + CL + DR) & 0xffffffff,
                (h2 + DL + ER) & 0xffffffff,
                (h3 + EL + AR) & 0xffffffff,
                (h4 + AL + BR) & 0xffffffff,
                (h0 + BL + CR) & 0xffffffff
            )

        return struct.pack('<5I', h0, h1, h2, h3, h4)

    @staticmethod
    def hash160(data: bytes) -> bytes:
        sha256_hash = hashlib.sha256(data).digest()
        return AddressGenerator.ripemd160(sha256_hash)

    @staticmethod
    def base58check_encode(payload: bytes) -> str:
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode('ascii')

    @staticmethod
    def bech32_encode(hrp: str, witness_version: int, program: bytes) -> str:
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        def bech32_polymod(values):
            generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for v in values:
                b = chk >> 25
                chk = (chk & 0x1ffffff) << 5 ^ v
                for i in range(5):
                    chk ^= generator[i] if ((b >> i) & 1) else 0
            return chk

        def bech32_hrp_expand(h):
            return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]

        def bech32_create_checksum(h, values):
            v = bech32_hrp_expand(h) + values
            polymod = bech32_polymod(v + [0, 0, 0, 0, 0, 0]) ^ 1
            return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

        def convertbits(data_bytes, frombits, tobits, pad=True):
            acc = 0
            bits = 0
            ret = []
            maxv = (1 << tobits) - 1
            for value in data_bytes:
                acc = (acc << frombits) | value
                bits += frombits
                while bits >= tobits:
                    bits -= tobits
                    ret.append((acc >> bits) & maxv)
            if pad and bits:
                ret.append((acc << (tobits - bits)) & maxv)
            return ret

        encoded = [witness_version] + convertbits(list(program), 8, 5)
        combined = encoded + bech32_create_checksum(hrp, encoded)
        return hrp + '1' + ''.join([charset[d] for d in combined])

    @staticmethod
    def bech32_decode(address: str) -> Optional[Tuple[int, bytes]]:
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        pos = address.rfind('1')
        if pos < 1 or pos + 7 > len(address):
            return None

        data_part = address[pos + 1:]
        hrp = address[:pos]

        decoded = []
        for char in data_part:
            if char not in charset:
                return None
            decoded.append(charset.index(char))

        def bech32_hrp_expand(h):
            return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]

        def bech32_polymod(values):
            generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for v in values:
                b = chk >> 25
                chk = (chk & 0x1ffffff) << 5 ^ v
                for i in range(5):
                    chk ^= generator[i] if ((b >> i) & 1) else 0
            return chk

        values = bech32_hrp_expand(hrp) + decoded
        if bech32_polymod(values) != 1:
            return None

        decoded = decoded[:-6]
        if len(decoded) < 1:
            return None

        witness_version = decoded[0]

        def convertbits(data_bytes, frombits, tobits, pad=False):
            acc = 0
            bits = 0
            ret = []
            maxv = (1 << tobits) - 1
            for value in data_bytes:
                acc = (acc << frombits) | value
                bits += frombits
                while bits >= tobits:
                    bits -= tobits
                    ret.append((acc >> bits) & maxv)
            if pad and bits:
                ret.append((acc << (tobits - bits)) & maxv)
            return ret

        witness_program = bytes(convertbits(decoded[1:], 5, 8))
        return (witness_version, witness_program)

    @classmethod
    def address_to_scriptpubkey(cls, address: str, chain: str) -> bytes:
        config = CHAIN_CONFIG.get(chain, {})
        bech32_hrp = config.get("bech32_hrp")
        
        if bech32_hrp and address.lower().startswith(bech32_hrp + "1"):
            decoded = cls.bech32_decode(address)
            if decoded:
                witness_version, witness_program = decoded
                op = 0x00 if witness_version == 0 else 0x50 + witness_version
                return bytes([op, len(witness_program)]) + witness_program

        try:
            decoded = base58.b58decode_check(address)
        except Exception:
            raise ValueError(f"Cannot decode address: {address}")

        version_byte = decoded[0:1]
        hash160_bytes = decoded[1:]

        p2pkh_version = config.get("p2pkh_version", b'\x00')
        p2sh_version = config.get("p2sh_version", b'\x05')

        if version_byte == p2pkh_version:
            return b'\x76\xa9\x14' + hash160_bytes + b'\x88\xac'
        elif version_byte == p2sh_version:
            return b'\xa9\x14' + hash160_bytes + b'\x87'
        else:
            return b'\x76\xa9\x14' + hash160_bytes + b'\x88\xac'

    @classmethod
    def address_to_scripthash(cls, address: str, chain: str) -> str:
        script = cls.address_to_scriptpubkey(address, chain)
        h = hashlib.sha256(script).digest()
        return h[::-1].hex()

    @staticmethod
    def keccak256(data: bytes) -> bytes:
        try:
            from Crypto.Hash import keccak
            k = keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()
        except ImportError:
            try:
                import sha3
                k = sha3.keccak_256()
                k.update(data)
                return k.digest()
            except ImportError:
                return AddressGenerator._keccak256_pure(data)

    @staticmethod
    def _keccak256_pure(data: bytes) -> bytes:
        state = [0] * 25

        RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ]

        r = [
            0,   1,  62,  28,  27,
           36,  44,   6,  55,  20,
            3,  10,  43,  25,  39,
           41,  45,  15,  21,   8,
           18,   2,  61,  56,  14
        ]

        rate = 136
        padded = bytearray(data)
        padded.append(0x01)
        while len(padded) % rate != (rate - 1):
            padded.append(0x00)
        padded.append(0x80)

        for block_idx in range(0, len(padded), rate):
            block = padded[block_idx:block_idx+rate]
            for i in range(17):
                val = int.from_bytes(block[i*8:(i+1)*8], 'little')
                state[i] ^= val

            for round_idx in range(24):
                C = [0] * 5
                for x in range(5):
                    C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                D = [0] * 5
                for x in range(5):
                    D[x] = C[(x-1)%5] ^ (((C[(x+1)%5] << 1) | (C[(x+1)%5] >> 63)) & 0xffffffffffffffff)
                for i in range(25):
                    state[i] ^= D[i % 5]

                next_state = [0] * 25
                for x in range(5):
                    for y in range(5):
                        idx = x + 5 * y
                        shift = r[idx]
                        val = state[idx]
                        rotated = ((val << shift) | (val >> (64 - shift))) & 0xffffffffffffffff
                        next_x = y
                        next_y = (2 * x + 3 * y) % 5
                        next_state[next_x + 5 * next_y] = rotated
                state = next_state

                next_state = list(state)
                for y in range(5):
                    for x in range(5):
                        idx = x + 5 * y
                        idx_x1 = ((x + 1) % 5) + 5 * y
                        idx_x2 = ((x + 2) % 5) + 5 * y
                        next_state[idx] = state[idx] ^ ((~state[idx_x1]) & state[idx_x2])
                state = next_state

                state[0] ^= RC[round_idx]

        out = bytearray()
        for i in range(4):
            out.extend(state[i].to_bytes(8, 'little'))
        return bytes(out)

    @classmethod
    def btc_legacy(cls, pubkey: bytes) -> str:
        return cls.base58check_encode(CHAIN_CONFIG["BTC"]["p2pkh_version"] + cls.hash160(pubkey))

    @classmethod
    def btc_segwit(cls, pubkey: bytes) -> str:
        pubkey_hash = cls.hash160(pubkey)
        redeem_script = b'\x00\x14' + pubkey_hash
        script_hash = cls.hash160(redeem_script)
        return cls.base58check_encode(CHAIN_CONFIG["BTC"]["p2sh_version"] + script_hash)

    @classmethod
    def btc_bech32(cls, pubkey: bytes) -> str:
        return cls.bech32_encode(CHAIN_CONFIG["BTC"]["bech32_hrp"], 0, cls.hash160(pubkey))

    @classmethod
    def ltc_legacy(cls, pubkey: bytes) -> str:
        return cls.base58check_encode(CHAIN_CONFIG["LTC"]["p2pkh_version"] + cls.hash160(pubkey))

    @classmethod
    def ltc_segwit(cls, pubkey: bytes) -> str:
        pubkey_hash = cls.hash160(pubkey)
        redeem_script = b'\x00\x14' + pubkey_hash
        script_hash = cls.hash160(redeem_script)
        return cls.base58check_encode(CHAIN_CONFIG["LTC"]["p2sh_version"] + script_hash)

    @classmethod
    def ltc_bech32(cls, pubkey: bytes) -> str:
        return cls.bech32_encode(CHAIN_CONFIG["LTC"]["bech32_hrp"], 0, cls.hash160(pubkey))

    @classmethod
    def eth_address(cls, pubkey: bytes) -> str:
        if pubkey[0] == 0x04:
            pub_key_xy = pubkey[1:]
        elif pubkey[0] in (0x02, 0x03):
            vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            pub_key_xy = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        else:
            raise ValueError(f"Invalid public key prefix: {pubkey[0]}")
        pubkey_hash = cls.keccak256(pub_key_xy)
        return '0x' + pubkey_hash[-20:].hex()

    @classmethod
    def doge_legacy(cls, pubkey: bytes) -> str:
        return cls.base58check_encode(CHAIN_CONFIG["DOGE"]["p2pkh_version"] + cls.hash160(pubkey))

    @classmethod
    def private_to_wif(cls, private_key: bytes, chain: str = "BTC", compressed: bool = True) -> str:
        wif_prefix = CHAIN_CONFIG[chain].get("wif_prefix")
        if wif_prefix is None:
            return private_key.hex()
        payload = wif_prefix + private_key
        if compressed:
            payload += b'\x01'
        return cls.base58check_encode(payload)

# ─── Wallet Generation Methods ──────────────────────────────────────────────

class WalletGenerator:
    def __init__(self):
        self.address_gen = AddressGenerator()

    def generate_bip39(self, chains: List[str], address_types: List[str], strength: int = 128, language: str = "english", passphrase: str = "") -> Dict:
        mnemonic, entropy_hex = BIP39Wordlist.generate_mnemonic_with_strength_and_entropy(strength, language)
        mnemonic_str = " ".join(mnemonic)
        seed = BIP39Wordlist.mnemonic_to_seed(mnemonic, passphrase)
        master_key, master_chain_code = BIP32Derivation.master_key_from_seed(seed)

        wallets = {}
        for chain in chains:
            config = CHAIN_CONFIG.get(chain)
            if not config: continue
            wallets[chain] = {}
            chain_addr_types = address_types
            if chain == "ETH": chain_addr_types = ["legacy"]
            elif chain == "DOGE": chain_addr_types = ["legacy"]

            for addr_type in chain_addr_types:
                path = config["derivation_paths"].get(addr_type)
                if not path: continue
                priv_key, _ = BIP32Derivation.derive_path(master_key, master_chain_code, path)
                pubkey = BIP32Derivation.private_to_public_key(priv_key, compressed=True)
                address = self._get_address(chain, addr_type, pubkey)
                wif = AddressGenerator.private_to_wif(priv_key, chain)
                wallets[chain][addr_type] = {
                    "address": address, "private_key": priv_key.hex(),
                    "wif": wif, "derivation_path": path, "pubkey": pubkey.hex()
                }
        return {"method": "bip39", "mnemonic": mnemonic_str, "seed": seed.hex(), "entropy": entropy_hex, "wallets": wallets}

    def generate_brain_wallet(self, passphrase: str, chains: List[str], address_types: List[str]) -> Dict:
        private_key = hashlib.sha256(passphrase.encode('utf-8')).digest()
        wallets = {}
        for chain in chains:
            if chain not in CHAIN_CONFIG: continue
            wallets[chain] = {}
            chain_addr_types = address_types
            if chain == "ETH": chain_addr_types = ["legacy"]
            elif chain == "DOGE": chain_addr_types = ["legacy"]

            for addr_type in chain_addr_types:
                config = CHAIN_CONFIG[chain]
                path = config["derivation_paths"].get(addr_type)
                if not path: continue
                pubkey = BIP32Derivation.private_to_public_key(private_key, compressed=True)
                address = self._get_address(chain, addr_type, pubkey)
                wif = AddressGenerator.private_to_wif(private_key, chain)
                wallets[chain][addr_type] = {
                    "address": address, "private_key": private_key.hex(),
                    "wif": wif, "passphrase": passphrase, "pubkey": pubkey.hex()
                }
        return {"method": "brain", "passphrase": passphrase, "wallets": wallets}

    def generate_raw_key(self, chains: List[str], address_types: List[str]) -> Dict:
        private_key = secrets.token_bytes(32)
        key_int = int.from_bytes(private_key, 'big')
        if key_int == 0 or key_int >= BIP32Derivation.SECP256K1_ORDER:
            private_key = secrets.token_bytes(32)

        wallets = {}
        for chain in chains:
            if chain not in CHAIN_CONFIG: continue
            wallets[chain] = {}
            chain_addr_types = address_types
            if chain == "ETH": chain_addr_types = ["legacy"]
            elif chain == "DOGE": chain_addr_types = ["legacy"]

            for addr_type in chain_addr_types:
                pubkey = BIP32Derivation.private_to_public_key(private_key, compressed=True)
                address = self._get_address(chain, addr_type, pubkey)
                wif = AddressGenerator.private_to_wif(private_key, chain)
                wallets[chain][addr_type] = {
                    "address": address, "private_key": private_key.hex(),
                    "wif": wif, "pubkey": pubkey.hex()
                }
        return {"method": "raw", "wallets": wallets}

    def generate_satoshi(self, chains: List[str], address_types: List[str]) -> Dict:
        private_key = secrets.token_bytes(32)
        key_int = int.from_bytes(private_key, 'big')
        if key_int == 0 or key_int >= BIP32Derivation.SECP256K1_ORDER:
            private_key = secrets.token_bytes(32)

        pubkey_compressed = BIP32Derivation.private_to_public_key(private_key, compressed=True)
        pubkey_uncompressed = BIP32Derivation.private_to_public_key(private_key, compressed=False)

        wallets = {}
        for chain in chains:
            if chain not in CHAIN_CONFIG: continue
            config = CHAIN_CONFIG[chain]
            if config["p2pkh_version"] is None: continue
            wallets[chain] = {}

            # Legacy compressed
            addr_legacy_comp = self.address_gen.base58check_encode(
                config["p2pkh_version"] + self.address_gen.hash160(pubkey_compressed)
            )
            wallets[chain]["legacy"] = {
                "address": addr_legacy_comp, "private_key": private_key.hex(),
                "wif": AddressGenerator.private_to_wif(private_key, chain, compressed=True),
                "pubkey": pubkey_compressed.hex(), "key_format": "compressed"
            }

            # Legacy uncompressed
            addr_legacy_uncomp = self.address_gen.base58check_encode(
                config["p2pkh_version"] + self.address_gen.hash160(pubkey_uncompressed)
            )
            wallets[chain]["uncompressed"] = {
                "address": addr_legacy_uncomp, "private_key": private_key.hex(),
                "wif": AddressGenerator.private_to_wif(private_key, chain, compressed=False),
                "pubkey": pubkey_uncompressed.hex(), "key_format": "uncompressed"
            }

            if "segwit" in address_types and config.get("p2sh_version"):
                addr_segwit = self._get_address(chain, "segwit", pubkey_compressed)
                wallets[chain]["segwit"] = {
                    "address": addr_segwit, "private_key": private_key.hex(),
                    "wif": AddressGenerator.private_to_wif(private_key, chain, compressed=True),
                    "pubkey": pubkey_compressed.hex(), "key_format": "compressed"
                }

            if "bech32" in address_types and config.get("bech32_hrp"):
                addr_bech32 = self._get_address(chain, "bech32", pubkey_compressed)
                wallets[chain]["bech32"] = {
                    "address": addr_bech32, "private_key": private_key.hex(),
                    "wif": AddressGenerator.private_to_wif(private_key, chain, compressed=True),
                    "pubkey": pubkey_compressed.hex(), "key_format": "compressed"
                }

        return {"method": "satoshi", "private_key": private_key.hex(), "wallets": wallets}

    def generate_mini_key(self, chains: List[str], address_types: List[str]) -> Dict:
        base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        mini_key = 'S'
        for _ in range(29):
            mini_key += secrets.choice(base58_chars)
        private_key = hashlib.sha256(mini_key.encode('ascii')).digest()

        wallets = {}
        for chain in chains:
            if chain not in CHAIN_CONFIG: continue
            wallets[chain] = {}
            chain_addr_types = address_types
            if chain == "ETH": chain_addr_types = ["legacy"]
            elif chain == "DOGE": chain_addr_types = ["legacy"]
            for addr_type in chain_addr_types:
                pubkey = BIP32Derivation.private_to_public_key(private_key, compressed=True)
                address = self._get_address(chain, addr_type, pubkey)
                wif = AddressGenerator.private_to_wif(private_key, chain)
                wallets[chain][addr_type] = {
                    "address": address, "private_key": private_key.hex(),
                    "wif": wif, "mini_key": mini_key, "pubkey": pubkey.hex()
                }
        return {"method": "mini", "mini_key": mini_key, "wallets": wallets}

    def generate_uncompressed(self, chains: List[str]) -> Dict:
        private_key = secrets.token_bytes(32)
        key_int = int.from_bytes(private_key, 'big')
        if key_int == 0 or key_int >= BIP32Derivation.SECP256K1_ORDER:
            private_key = secrets.token_bytes(32)

        pubkey_compressed = BIP32Derivation.private_to_public_key(private_key, compressed=True)
        pubkey_uncompressed = BIP32Derivation.private_to_public_key(private_key, compressed=False)
        
        wallets = {}
        for chain in chains:
            if chain not in CHAIN_CONFIG: continue
            config = CHAIN_CONFIG[chain]
            if config["p2pkh_version"] is None: continue
            
            addr_uncompressed = self.address_gen.base58check_encode(
                config["p2pkh_version"] + self.address_gen.hash160(pubkey_uncompressed)
            )
            addr_compressed = self.address_gen.base58check_encode(
                config["p2pkh_version"] + self.address_gen.hash160(pubkey_compressed)
            )
            
            wallets[chain] = {
                "uncompressed": {
                    "address": addr_uncompressed, "private_key": private_key.hex(),
                    "wif": AddressGenerator.private_to_wif(private_key, chain, compressed=False),
                    "pubkey": pubkey_uncompressed.hex()
                },
                "compressed": {
                    "address": addr_compressed, "private_key": private_key.hex(),
                    "wif": AddressGenerator.private_to_wif(private_key, chain, compressed=True),
                    "pubkey": pubkey_compressed.hex()
                }
            }
        return {"method": "uncompressed", "wallets": wallets}

    def generate_vanity(self, prefix: str, chain: str = "BTC", addr_type: str = "legacy") -> Dict:
        attempts = 0
        while True:
            attempts += 1
            private_key = secrets.token_bytes(32)
            key_int = int.from_bytes(private_key, 'big')
            if key_int == 0 or key_int >= BIP32Derivation.SECP256K1_ORDER:
                continue
            
            pubkey = BIP32Derivation.private_to_public_key(private_key, compressed=True)
            address = self._get_address(chain, addr_type, pubkey)
            if address.lower().startswith(prefix.lower()):
                return {
                    "method": "vanity", "prefix": prefix, "address": address,
                    "private_key": private_key.hex(), "wif": AddressGenerator.private_to_wif(private_key, chain),
                    "pubkey": pubkey.hex(), "attempts": attempts
                }
            if attempts % 100000 == 0:
                logging.info(f"Vanity search: {attempts:,} attempts...")

    def generate_from_mnemonic(self, mnemonic_str: str, chains: List[str], address_types: List[str]) -> Dict:
        mnemonic = mnemonic_str.strip().split()
        seed = BIP39Wordlist.mnemonic_to_seed(mnemonic)
        master_key, master_chain_code = BIP32Derivation.master_key_from_seed(seed)
        
        wallets = {}
        for chain in chains:
            if chain not in CHAIN_CONFIG: continue
            config = CHAIN_CONFIG[chain]
            wallets[chain] = {}
            
            chain_addr_types = address_types
            if chain == "ETH": chain_addr_types = ["legacy"]
            elif chain == "DOGE": chain_addr_types = ["legacy"]
            
            for addr_type in chain_addr_types:
                path = config["derivation_paths"].get(addr_type)
                if not path: continue
                priv_key, _ = BIP32Derivation.derive_path(master_key, master_chain_code, path)
                pubkey = BIP32Derivation.private_to_public_key(priv_key, compressed=True)
                address = self._get_address(chain, addr_type, pubkey)
                wif = AddressGenerator.private_to_wif(priv_key, chain)
                wallets[chain][addr_type] = {
                    "address": address, "private_key": priv_key.hex(),
                    "wif": wif, "derivation_path": path, "pubkey": pubkey.hex()
                }
        return {"method": "imported_mnemonic", "mnemonic": mnemonic_str, "wallets": wallets}

    def _get_address(self, chain: str, addr_type: str, pubkey: bytes) -> str:
        if chain == "BTC":
            if addr_type == "legacy": return self.address_gen.btc_legacy(pubkey)
            if addr_type == "segwit": return self.address_gen.btc_segwit(pubkey)
            if addr_type == "bech32": return self.address_gen.btc_bech32(pubkey)
        elif chain == "LTC":
            if addr_type == "legacy": return self.address_gen.ltc_legacy(pubkey)
            if addr_type == "segwit": return self.address_gen.ltc_segwit(pubkey)
            if addr_type == "bech32": return self.address_gen.ltc_bech32(pubkey)
        elif chain == "ETH":
            return self.address_gen.eth_address(pubkey)
        elif chain == "DOGE":
            return self.address_gen.doge_legacy(pubkey)
        raise ValueError(f"Unsupported chain/address type: {chain}/{addr_type}")

# ─── Proxy Manager ───────────────────────────────────────────────────────────

class ProxyManager:
    def __init__(self, proxy_file: Optional[str] = None, proxy_type: str = "http"):
        self.proxy_type = proxy_type
        self.proxies: deque = deque()
        self.dead_proxies: set = set()
        self.lock = threading.Lock()
        self.enabled = False
        if proxy_file: self.load_proxies(proxy_file)

    def load_proxies(self, filepath: str) -> int:
        loaded = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    parts = line.split(':')
                    if len(parts) == 2:
                        proxy_str = f"{self.proxy_type}://{parts[0]}:{parts[1]}"
                    elif len(parts) == 4:
                        proxy_str = f"{self.proxy_type}://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
                    else:
                        proxy_str = f"{self.proxy_type}://{line}"
                    self.proxies.append(proxy_str)
                    loaded += 1
            self.enabled = loaded > 0
        except Exception: pass
        return loaded

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.enabled or not self.proxies: return None
        with self.lock:
            if not self.proxies: return None
            proxy = self.proxies[0]
            self.proxies.rotate(1)
            return {"http": proxy, "https": proxy}

    def mark_dead(self, proxy_dict: Optional[Dict[str, str]]):
        if not proxy_dict or not self.enabled: return
        with self.lock:
            proxy_url = proxy_dict.get("http", "")
            if proxy_url in self.proxies:
                self.proxies.remove(proxy_url)
                self.dead_proxies.add(proxy_url)

# ─── ElectrumX Client ──────────────────────────────────────────────────────

class ElectrumClient:
    def __init__(self, servers: List[Dict], timeout: int = 10):
        self.servers = servers
        self.timeout = timeout
        self.local = threading.local()
        self.request_id = 0
        self.id_lock = threading.Lock()
        self.server_index = 0
        self.server_lock = threading.Lock()

    def _pick_server(self) -> Dict:
        with self.server_lock:
            server = self.servers[self.server_index % len(self.servers)]
            self.server_index += 1
            return server

    def _connect(self) -> bool:
        tried = set()
        for _ in range(len(self.servers)):
            server = self._pick_server()
            key = f"{server['host']}:{server['port']}"
            if key in tried: continue
            tried.add(key)
            try:
                sock = socket.create_connection((server['host'], server['port']), timeout=self.timeout)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ssl_sock = ctx.wrap_socket(sock, server_hostname=server['host'])
                ssl_sock.settimeout(self.timeout)
                self.local.conn = ssl_sock
                return True
            except Exception: continue
        self.local.conn = None
        return False

    def _get_conn(self):
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            if not self._connect(): return None
        return self.local.conn

    def query(self, method: str, params: List) -> Optional[Any]:
        conn = self._get_conn()
        if not conn: return None
        with self.id_lock:
            self.request_id += 1
            req_id = self.request_id
        request_line = json.dumps({"id": req_id, "method": method, "params": params}) + "\n"
        try:
            conn.sendall(request_line.encode('utf-8'))
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(8192)
                if not chunk: raise ConnectionError("Closed")
                buf += chunk
            response = json.loads(buf.decode('utf-8').strip().split('\n')[0])
            if response.get("error"): return None
            return response.get("result")
        except Exception:
            self.local.conn = None
            return None

    def check_address(self, address: str, chain: str) -> Optional[Dict]:
        scripthash = AddressGenerator.address_to_scripthash(address, chain)
        balance_result = self.query("blockchain.scripthash.get_balance", [scripthash])
        if balance_result is None: return None
        total_balance = balance_result.get("confirmed", 0) + balance_result.get("unconfirmed", 0)
        history = self.query("blockchain.scripthash.get_history", [scripthash])
        tx_count = len(history) if history else 0
        divisor = 1e18 if chain == "ETH" else 1e8
        
        # Estimate received balance
        received = total_balance if total_balance > 0 else (1 if tx_count > 0 else 0)
        return {
            "balance": total_balance, "balance_coin": total_balance / divisor,
            "received": received, "received_coin": received / divisor,
            "tx_count": tx_count, "has_activity": tx_count > 0 or total_balance > 0,
            "api_source": "electrumx", "chain": chain, "address": address
        }

# ─── Blockchain API Checker ─────────────────────────────────────────────────

class BlockchainChecker:
    def __init__(self, proxy_manager: ProxyManager, timeout: int = 15, max_retries: int = 3):
        self.proxy_manager = proxy_manager
        self.timeout = timeout
        self.max_retries = max_retries
        self.session_pool = {}
        self.api_rate_limits = {}
        self.rate_lock = threading.Lock()
        self.rpc_index = 0
        self.rpc_lock = threading.Lock()
        self.electrum_clients = {chain: ElectrumClient(servers, timeout) for chain, servers in ELECTRUM_SERVERS.items()}
        self._build_sessions()

    def _build_sessions(self):
        for chain, config in CHAIN_CONFIG.items():
            for endpoint in config["api_endpoints"]:
                name = endpoint["name"]
                session = requests.Session()
                retry = Retry(total=self.max_retries, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET"])
                adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                self.session_pool[name] = session
                self.api_rate_limits[name] = 0.0

    def _respect_rate_limit(self, endpoint_name: str, min_interval_ms: int):
        with self.rate_lock:
            last_call = self.api_rate_limits.get(endpoint_name, 0.0)
            elapsed = time.time() - last_call
            if elapsed < (min_interval_ms / 1000.0): time.sleep((min_interval_ms / 1000.0) - elapsed)
            self.api_rate_limits[endpoint_name] = time.time()

    def _make_request(self, url: str, endpoint_name: str, rate_limit_ms: int) -> Optional[dict]:
        self._respect_rate_limit(endpoint_name, rate_limit_ms)
        proxies = self.proxy_manager.get_proxy()
        session = self.session_pool.get(endpoint_name)
        for attempt in range(self.max_retries):
            try:
                response = session.get(url, timeout=self.timeout, proxies=proxies)
                response.raise_for_status()
                return response.json()
            except Exception: continue
        return None

    def _make_eth_rpc_call(self, address: str) -> Optional[Dict]:
        with self.rpc_lock:
            rpc_url = ETH_RPC_ENDPOINTS[self.rpc_index % len(ETH_RPC_ENDPOINTS)]
            self.rpc_index += 1
        payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}
        for attempt in range(self.max_retries):
            try:
                with self.rpc_lock:
                    rpc_url = ETH_RPC_ENDPOINTS[(self.rpc_index + attempt) % len(ETH_RPC_ENDPOINTS)]
                proxies = self.proxy_manager.get_proxy()
                response = requests.post(rpc_url, json=payload, timeout=self.timeout, proxies=proxies)
                response.raise_for_status()
                data = response.json()
                balance_hex = data.get("result", "0x0")
                balance_wei = int(balance_hex, 16) if balance_hex.startswith("0x") else int(balance_hex)
                return {"balance": balance_wei, "balance_coin": balance_wei / 1e18, "received": balance_wei, "received_coin": balance_wei / 1e18, "has_activity": balance_wei > 0, "api_source": "eth_rpc", "chain": "ETH", "address": address}
            except Exception: continue
        return None

    def _parse_blockchain_info(self, data, addr): 
        addr_data = data.get(addr, {})
        bal = addr_data.get("final_balance", 0)
        rec = addr_data.get("total_received", 0)
        return {"balance": bal, "balance_coin": bal/1e8, "received": rec, "received_coin": rec/1e8, "has_activity": rec > 0 or bal > 0}
        
    def _parse_blockcypher(self, data, addr): 
        bal = data.get("balance", 0)
        rec = data.get("total_received", 0)
        return {"balance": bal, "balance_coin": bal/1e8, "received": rec, "received_coin": rec/1e8, "has_activity": rec > 0 or bal > 0}

    def _parse_blockcypher_eth(self, data, addr): 
        bal = data.get("balance", 0)
        rec = data.get("total_received", 0)
        return {"balance": bal, "balance_coin": bal/1e18, "received": rec, "received_coin": rec/1e18, "has_activity": rec > 0 or bal > 0}

    def _parse_mempool_space(self, data, addr):
        chain_stats = data.get("chain_stats", {})
        mempool_stats = data.get("mempool_stats", {})
        funded = chain_stats.get("funded_txo_sum", 0) + mempool_stats.get("funded_txo_sum", 0)
        spent = chain_stats.get("spent_txo_sum", 0) + mempool_stats.get("spent_txo_sum", 0)
        bal = funded - spent
        return {"balance": bal, "balance_coin": bal/1e8, "received": funded, "received_coin": funded/1e8, "has_activity": funded > 0 or bal > 0}

    def _parse_etherscan(self, data, addr):
        bal = int(data.get("result", "0")) if data.get("status") == "1" else 0
        return {"balance": bal, "balance_coin": bal/1e18, "received": bal, "received_coin": bal/1e18, "has_activity": bal > 0}

    def _parse_ethplorer(self, data, addr):
        bal = int(data.get("ETH", {}).get("rawBalance", 0)) if data.get("ETH") else 0
        return {"balance": bal, "balance_coin": bal/1e18, "received": bal, "received_coin": bal/1e18, "has_activity": bal > 0}

    def _parse_ltc_explorer(self, data, addr):
        bal = data.get("balance", 0)
        rec = data.get("totalReceived", 0)
        return {"balance": bal, "balance_coin": bal/1e8, "received": rec, "received_coin": rec/1e8, "has_activity": rec > 0 or bal > 0}

    PARSERS = {
        "blockchain_info": _parse_blockchain_info, "blockcypher": _parse_blockcypher,
        "blockcypher_eth": _parse_blockcypher_eth,
        "mempool_space": _parse_mempool_space, "etherscan": _parse_etherscan,
        "ethplorer": _parse_ethplorer, "ltc_explorer": _parse_ltc_explorer
    }

    def _check_rest_apis(self, address: str, chain: str) -> Optional[Dict]:
        config = CHAIN_CONFIG.get(chain)
        if not config: return None
        endpoints = list(config["api_endpoints"])
        random.shuffle(endpoints)
        for endpoint in endpoints:
            url = endpoint["url"].format(address=address)
            data = self._make_request(url, endpoint["name"], endpoint.get("rate_limit_ms", 500))
            if data is not None:
                parser = self.PARSERS.get(endpoint["parser"])
                if parser:
                    try:
                        result = parser(self, data, address)
                        result["api_source"] = endpoint["name"]
                        result["chain"] = chain
                        result["address"] = address
                        return result
                    except Exception: continue
        return None

    def check_address(self, address: str, chain: str) -> Optional[Dict]:
        if chain in self.electrum_clients:
            result = self.electrum_clients[chain].check_address(address, chain)
            if result is not None: return result
        if chain == "ETH":
            result = self._make_eth_rpc_call(address)
            if result is not None: return result
        return self._check_rest_apis(address, chain)

    def check_wallet(self, wallet_data: Dict, chains: List[str]) -> Dict:
        results = {}
        for chain in chains:
            if chain not in wallet_data.get("wallets", {}): continue
            results[chain] = {}
            for addr_type, wallet_info in wallet_data["wallets"][chain].items():
                result = self.check_address(wallet_info["address"], chain)
                if result:
                    results[chain][addr_type] = result
                    if result.get("balance", 0) > 0:
                        results[chain][addr_type]["FOUND_BALANCE"] = True
                        results[chain][addr_type]["wallet_info"] = wallet_info
                    elif result.get("has_activity", False):
                        results[chain][addr_type]["FOUND_ACTIVITY"] = True
                        results[chain][addr_type]["wallet_info"] = wallet_info
                else:
                    results[chain][addr_type] = {
                        "address": wallet_info["address"],
                        "error": "Failed",
                        "has_activity": False,
                        "balance": 0
                    }
        return results

# ─── Statistics & Handlers ──────────────────────────────────────────────────

class StatisticsTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.wallets_checked = 0
        self.addresses_checked = 0
        self.wallets_with_balance = 0
        self.wallets_with_activity = 0
        self.api_calls = 0
        self.api_failures = 0
        self.chains_checked = defaultdict(int)
        self.methods_used = defaultdict(int)
        self.found_wallets = []

    def record_check(self, wallet_data: Dict, results: Dict):
        with self.lock:
            self.wallets_checked += 1
            self.methods_used[wallet_data.get("method", "unknown")] += 1
            for chain, chain_results in results.items():
                self.chains_checked[chain] += 1
                for addr_type, result in chain_results.items():
                    self.addresses_checked += 1
                    self.api_calls += 1
                    if result.get("error"): self.api_failures += 1
                    
                    if result.get("FOUND_BALANCE"):
                        self.wallets_with_balance += 1
                        self.found_wallets.append({
                            "address": result["address"],
                            "mnemonic": wallet_data.get("mnemonic", ""),
                            "type": "balance"
                        })
                    elif result.get("FOUND_ACTIVITY"):
                        self.wallets_with_activity += 1
                        self.found_wallets.append({
                            "address": result["address"],
                            "mnemonic": wallet_data.get("mnemonic", ""),
                            "type": "activity"
                        })

    def get_stats(self) -> Dict:
        with self.lock:
            elapsed = time.time() - self.start_time
            return {
                "elapsed_formatted": str(timedelta(seconds=int(elapsed))),
                "wallets_checked": self.wallets_checked,
                "addresses_checked": self.addresses_checked,
                "wallets_with_balance": self.wallets_with_balance,
                "wallets_with_activity": self.wallets_with_activity,
                "api_calls": self.api_calls,
                "api_failures": self.api_failures,
                "api_success_rate": ((self.api_calls - self.api_failures) / self.api_calls * 100) if self.api_calls > 0 else 0,
                "wallets_per_second": self.wallets_checked / elapsed if elapsed > 0 else 0,
                "addresses_per_second": self.addresses_checked / elapsed if elapsed > 0 else 0,
                "chains_checked": dict(self.chains_checked),
                "methods_used": dict(self.methods_used),
                "found_count": len(self.found_wallets),
            }

class FoundWalletHandler:
    def __init__(self, output_dir: str = "found_wallets", webhook_url: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url
        self.lock = threading.Lock()
        self.found_file = self.output_dir / f"found_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        with open(self.found_file, 'w') as f: f.write("")

    def record_found(self, found_data: Dict):
        with self.lock:
            with open(self.found_file, 'a') as f:
                f.write(json.dumps(found_data) + '\n')
            logging.info(f"🎉 WALLET FOUND! {found_data.get('chain')} {found_data.get('address')} - Bal: {found_data.get('balance_coin', 0):.8f}")
            if self.webhook_url:
                try: requests.post(self.webhook_url, json={"content": f"💰 Found: {found_data.get('address')} | Bal: {found_data.get('balance_coin')}"})
                except Exception: pass

# ─── Main Wallet Hunter Engine ──────────────────────────────────────────────

class WalletHunter:
    def __init__(
        self, display_interval: int = 5, method: str = "bip39", chains: List[str] = None,
        address_types: List[str] = None, num_threads: int = 8, proxy_file: Optional[str] = None,
        proxy_type: str = "http", output_dir: str = "found_wallets", webhook_url: Optional[str] = None,
        api_timeout: int = 15, max_retries: int = 3, save_interval: int = 60,
        vanity_prefix: Optional[str] = None, brain_passphrases: Optional[str] = None,
        check_interval: float = 0.0, stats_callback: Callable = None,
    ):
        self.method = method
        self.chains = chains or ["BTC"]
        self.address_types = address_types or ["legacy", "segwit", "bech32"]
        self.num_threads = num_threads
        self.vanity_prefix = vanity_prefix
        self.brain_passphrases_file = brain_passphrases
        self.check_interval = check_interval
        self.display_interval = display_interval
        self.stats_callback = stats_callback

        self.generator = WalletGenerator()
        self.proxy_manager = ProxyManager(proxy_file, proxy_type)
        self.checker = BlockchainChecker(self.proxy_manager, api_timeout, max_retries)
        self.stats = StatisticsTracker()
        self.found_handler = FoundWalletHandler(output_dir, webhook_url)
        self.save_interval = save_interval

        self.running = threading.Event()
        self.running.set()
        self.workers = []
        self.stop_event = threading.Event()

        self.brain_passphrases = deque()
        if brain_passphrases and os.path.exists(brain_passphrases):
            with open(brain_passphrases, 'r') as f:
                for line in f:
                    if line.strip(): self.brain_passphrases.append(line.strip())

    def _worker_loop(self, worker_id: int):
        while self.running.is_set() and not self.stop_event.is_set():
            try:
                if self.method == "bip39": wallet_data = self.generator.generate_bip39(self.chains, self.address_types, b_config_strenght, b_config_language, b_config_passphere)
                elif self.method == "satoshi": wallet_data = self.generator.generate_satoshi(self.chains, self.address_types)
                elif self.method == "brain":
                    if self.brain_passphrases:
                        try: passphrase = self.brain_passphrases.popleft()
                        except IndexError: break
                        wallet_data = self.generator.generate_brain_wallet(passphrase, self.chains, self.address_types)
                    else:
                        wallet_data = self.generator.generate_brain_wallet(secrets.token_hex(16), self.chains, self.address_types)
                elif self.method == "raw": wallet_data = self.generator.generate_raw_key(self.chains, self.address_types)
                elif self.method == "mini": wallet_data = self.generator.generate_mini_key(self.chains, self.address_types)
                elif self.method == "uncompressed": wallet_data = self.generator.generate_uncompressed(self.chains)
                elif self.method == "vanity":
                    if not self.vanity_prefix: break
                    wallet_data = self.generator.generate_vanity(self.vanity_prefix, self.chains[0], self.address_types[0])
                    s_key = wallet_data["private_key"]
                    s_addr = wallet_data["address"]
                    s_wif = wallet_data["wif"]
                    s_pub = wallet_data["pubkey"]
                    wallet_data = {"method": "vanity", "wallets": {self.chains[0]: {self.address_types[0]: {
                        "address": s_addr, "private_key": s_key, "wif": s_wif, "pubkey": s_pub
                    }}}}
                else:
                    break

                addr_summary = [f"{c}({t}): {i['address']}" for c, w in wallet_data.get("wallets", {}).items() for t, i in w.items()]
                mnemonic_str = wallet_data.get("mnemonic") or wallet_data.get("passphrase") or wallet_data.get("mini_key") or wallet_data.get("private_key", "N/A")

                results = self.checker.check_wallet(wallet_data, self.chains)
                self.stats.record_check(wallet_data, results)

                api_sources = set()
                for chain, chain_results in results.items():
                    for addr_type, result in chain_results.items():
                        if "api_source" in result:
                            api_sources.add(result["api_source"])
                        if "error" in result:
                            api_sources.add("FAILED")

                for chain, chain_results in results.items():
                    for addr_type, result in chain_results.items():
                        if result.get("FOUND_BALANCE"):
                            self.found_handler.record_found({
                                "timestamp": datetime.now().isoformat(), "method": self.method, "chain": chain,
                                "addr_type": addr_type, "address": result["address"],
                                "balance": result.get("balance", 0),
                                "balance_coin": result.get("balance_coin", 0),
                                "mnemonic": wallet_data.get("mnemonic", ""),
                                "private_key": result.get("wallet_info", {}).get("private_key", ""),
                                "type": "balance"
                            })
                        elif result.get("FOUND_ACTIVITY"):
                            self.found_handler.record_found({
                                "timestamp": datetime.now().isoformat(), "method": self.method, "chain": chain,
                                "addr_type": addr_type, "address": result["address"],
                                "balance": 0,
                                "balance_coin": 0,
                                "mnemonic": wallet_data.get("mnemonic", ""),
                                "private_key": result.get("wallet_info", {}).get("private_key", ""),
                                "type": "activity"
                            })

                api_str = ", ".join(api_sources) if api_sources else "None"
                logging.info(f"Worker {worker_id}: #{self.stats.get_stats()['wallets_checked']} | API: [{api_str}] | {' | '.join(addr_summary)} | Mnemonic: {mnemonic_str}")

                if self.check_interval > 0: time.sleep(self.check_interval)
            except Exception as e:
                logging.error(f"Worker {worker_id} error: {e}\n{traceback.format_exc()}")

    def _stats_display_loop(self):
        last_save = time.time()
        while self.running.is_set() and not self.stop_event.is_set():
            stats = self.stats.get_stats()
            if self.stats_callback:
                self.stats_callback(stats)
            elif HAS_RICH:
                console.clear()
                console.print(Panel.fit(Text("⚡ MULTI-CHAIN WALLET HUNTER ⚡", style="bold cyan", justify="center"), border_style="cyan"))
                table = Table(title="Live Statistics", border_style="blue")
                table.add_column("Metric", style="cyan"); table.add_column("Value", style="yellow")
                for k, v in stats.items():
                    if isinstance(v, dict): continue
                    table.add_row(k.replace("_", " ").title(), f"{v:,}" if isinstance(v, int) else str(v))
                console.print(table)
            else:
                print(f"\rChecked: {stats['wallets_checked']} | Found: {stats['found_count']} | Speed: {stats['wallets_per_second']:.2f} w/s", end="")
            
            if time.time() - last_save >= self.save_interval: last_save = time.time()
            time.sleep(self.display_interval)

    def start(self):
        logging.info(f"Starting Wallet Hunter | Method: {self.method} | Chains: {', '.join(self.chains)} | Threads: {self.num_threads}")
        self.stats_thread = threading.Thread(target=self._stats_display_loop, daemon=True)
        self.stats_thread.start()
        for i in range(self.num_threads):
            worker = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            worker.start()
            self.workers.append(worker)

    def stop(self):
        self.stop_event.set()
        self.running.clear()
        for worker in self.workers: worker.join(timeout=2)
        logging.info("Wallet Hunter stopped.")

def check_single_wallet(mnemonic: str, chains: List[str], address_types: List[str], proxy_file: Optional[str] = None):
    generator = WalletGenerator()
    proxy_manager = ProxyManager(proxy_file) if proxy_file else ProxyManager()
    checker = BlockchainChecker(proxy_manager)
    wallet_data = generator.generate_from_mnemonic(mnemonic, chains, address_types)
    return checker.check_wallet(wallet_data, chains)

# ─── GUI Interface ───────────────────────────────────────────────────────────

class WalletHunterGUI:
    def __init__(self, root: 'tk.Tk'):
        self.root = root
        self.root.title("⚡ Multi-Chain Hunter")
        self.root.geometry("900x750")
        self.root.configure(bg='#1e1e1e')
        self.hunter = None
        self.is_running = False
        self.log_queue = queue.Queue()
        self._build_styles()
        self._build_ui()
        self._start_log_poller()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#e0e0e0', font=('Consolas', 10))
        style.configure('TButton', background='#333333', foreground='#ffffff', font=('Consolas', 10, 'bold'))
        style.configure('Start.TButton', background='#2d5a2d', foreground='#ffffff', font=('Consolas', 12, 'bold'))
        style.configure('Stop.TButton', background='#5a2d2d', foreground='#ffffff', font=('Consolas', 12, 'bold'))
        style.configure('TCheckbutton', background='#1e1e1e', foreground='#e0e0e0', font=('Consolas', 10))
        style.configure('TEntry', fieldbackground='#2d2d2d', foreground='#e0e0e0', font=('Consolas', 10))
        style.configure('TCombobox', fieldbackground='#2d2d2d', background='#333333', foreground='#e0e0e0', font=('Consolas', 10))
        style.configure('TSpinbox', fieldbackground='#2d2d2d', foreground='#e0e0e0', font=('Consolas', 10))
        style.configure('Header.TLabel', background='#1e1e1e', foreground='#00ffff', font=('Consolas', 14, 'bold'))
        style.configure('Section.TLabel', background='#1e1e1e', foreground='#ffaa00', font=('Consolas', 10, 'bold'))

    def _build_ui(self):
        ttk.Label(self.root, text="⚡ MULTI-CHAIN WALLET HUNTER & CHECKER", style='Header.TLabel').pack(pady=10)

        config_frame = ttk.Frame(self.root)
        config_frame.pack(fill='x', padx=20, pady=5)

        row1 = ttk.Frame(config_frame); row1.pack(fill='x', pady=3)
        ttk.Label(row1, text="Method:", width=15).pack(side='left')
        self.method_var = tk.StringVar(value="bip39")
        method_combo = ttk.Combobox(row1, textvariable=self.method_var, values=list(GEN_METHODS.keys()), state='readonly', width=30)
        method_combo.pack(side='left', padx=5); method_combo.bind('<<ComboboxSelected>>', self._on_method_change)

        row2 = ttk.Frame(config_frame); row2.pack(fill='x', pady=3)
        ttk.Label(row2, text="Chains:", width=15).pack(side='left')
        self.chain_vars = {}
        for chain in CHAIN_CONFIG.keys():
            var = tk.BooleanVar(value=(chain == "BTC"))
            ttk.Checkbutton(row2, text=chain, variable=var).pack(side='left', padx=10)
            self.chain_vars[chain] = var

        row3 = ttk.Frame(config_frame); row3.pack(fill='x', pady=3)
        ttk.Label(row3, text="Address Types:", width=15).pack(side='left')
        self.addr_type_vars = {}
        for addr_type in ["legacy", "segwit", "bech32"]:
            var = tk.BooleanVar(value=True)
            ttk.Checkbutton(row3, text=addr_type, variable=var).pack(side='left', padx=10)
            self.addr_type_vars[addr_type] = var

        row4 = ttk.Frame(config_frame); row4.pack(fill='x', pady=3)
        ttk.Label(row4, text="Threads:", width=10).pack(side='left')
        self.threads_var = tk.IntVar(value=32)
        ttk.Spinbox(row4, from_=1, to=512, textvariable=self.threads_var, width=6).pack(side='left', padx=5)
        ttk.Label(row4, text="Timeout (s):").pack(side='left', padx=(20, 0))
        self.timeout_var = tk.IntVar(value=10)
        ttk.Spinbox(row4, from_=1, to=120, textvariable=self.timeout_var, width=6).pack(side='left', padx=5)
        ttk.Label(row4, text="Retries:").pack(side='left', padx=(20, 0))
        self.retries_var = tk.IntVar(value=3)
        ttk.Spinbox(row4, from_=0, to=10, textvariable=self.retries_var, width=6).pack(side='left', padx=5)

        row5 = ttk.Frame(config_frame); row5.pack(fill='x', pady=3)
        ttk.Label(row5, text="Proxy File:", width=15).pack(side='left')
        self.proxy_file_var = tk.StringVar()
        ttk.Entry(row5, textvariable=self.proxy_file_var, width=40).pack(side='left', padx=5)
        ttk.Button(row5, text="Browse", command=self._browse_proxy).pack(side='left', padx=5)
        ttk.Label(row5, text="Type:").pack(side='left', padx=(10, 0))
        self.proxy_type_var = tk.StringVar(value="http")
        ttk.Combobox(row5, textvariable=self.proxy_type_var, values=["http", "https", "socks5", "socks4"], state='readonly', width=8).pack(side='left', padx=5)

        row6 = ttk.Frame(config_frame); row6.pack(fill='x', pady=3)
        ttk.Label(row6, text="Webhook URL:", width=15).pack(side='left')
        self.webhook_var = tk.StringVar()
        ttk.Entry(row6, textvariable=self.webhook_var, width=50).pack(side='left', padx=5)

        self.row7 = ttk.Frame(config_frame)
        ttk.Label(self.row7, text="Vanity Prefix:", width=15).pack(side='left')
        self.vanity_var = tk.StringVar()
        ttk.Entry(self.row7, textvariable=self.vanity_var, width=20).pack(side='left', padx=5)

        self.row8 = ttk.Frame(config_frame)
        ttk.Label(self.row8, text="Passphrase File:", width=15).pack(side='left')
        self.passphrase_file_var = tk.StringVar()
        ttk.Entry(self.row8, textvariable=self.passphrase_file_var, width=40).pack(side='left', padx=5)
        ttk.Button(self.row8, text="Browse", command=self._browse_passphrases).pack(side='left', padx=5)

        row9 = ttk.Frame(config_frame); row9.pack(fill='x', pady=3)
        ttk.Label(row9, text="Check Mnemonic:", width=15).pack(side='left')
        self.mnemonic_var = tk.StringVar()
        ttk.Entry(row9, textvariable=self.mnemonic_var, width=50).pack(side='left', padx=5)

        btn_frame = ttk.Frame(self.root); btn_frame.pack(pady=10)
        self.start_btn = ttk.Button(btn_frame, text="▶ START HUNTING", style='Start.TButton', command=self._start)
        self.start_btn.pack(side='left', padx=20)
        self.stop_btn = ttk.Button(btn_frame, text="■ STOP", style='Stop.TButton', command=self._stop, state='disabled')
        self.stop_btn.pack(side='left', padx=20)

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill='both', expand=True, padx=20, pady=5)

        ttk.Label(bottom_frame, text="Live Statistics", style='Section.TLabel').pack(anchor='w')
        self.stats_text = tk.Text(bottom_frame, height=12, bg='#0d0d0d', fg='#00ff00', font=('Consolas', 10), wrap='word', state='disabled')
        self.stats_text.pack(fill='x', pady=(0, 5))

        ttk.Label(bottom_frame, text="Check Logs", style='Section.TLabel').pack(anchor='w')
        self.log_frame = ttk.Frame(bottom_frame)
        self.log_frame.pack(fill='both', expand=True)

        self.log_text = tk.Text(self.log_frame, bg='#0a0a0a', fg='#00aa00', font=('Consolas', 9), wrap='word', state='disabled')
        self.log_text.pack(side='left', fill='both', expand=True)

        log_scrollbar = ttk.Scrollbar(self.log_frame, orient='vertical', command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side='right', fill='y')

        self.stats_text.tag_configure('found', foreground='#ffff00', font=('Consolas', 10, 'bold'))
        self.stats_text.tag_configure('stat', foreground='#00ffff')
        self.stats_text.tag_configure('header', foreground='#ffaa00', font=('Consolas', 10, 'bold'))

        self.log_text.tag_configure('found', foreground='#ffff00', font=('Consolas', 9, 'bold'))
        self.log_text.tag_configure('error', foreground='#ff4444')
        self.log_text.tag_configure('info', foreground='#00aa00')
        self.log_text.tag_configure('warning', foreground='#ffaa00')

    def _start_log_poller(self):
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                self._update_log_text(msg, level)
        except queue.Empty:
            pass
        self.root.after(100, self._start_log_poller)

    def _update_log_text(self, message: str, tag: str):
        self.log_text.configure(state='normal')
        self.log_text.insert('end', message + '\n', tag)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def _on_method_change(self, event=None):
        if self.method_var.get() == "vanity": self.row7.pack(fill='x', pady=3)
        else: self.row7.pack_forget()
        if self.method_var.get() == "brain": self.row8.pack(fill='x', pady=3)
        else: self.row8.pack_forget()

    def _browse_proxy(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath: self.proxy_file_var.set(filepath)

    def _browse_passphrases(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath: self.passphrase_file_var.set(filepath)

    def _log(self, message: str, tag: str = 'info'):
        self.log_queue.put((message, tag))

    def _stats_callback(self, stats: Dict):
        def update():
            self.stats_text.configure(state='normal')
            self.stats_text.delete('1.0', 'end')
            self.stats_text.insert('end', "═══════════════════════════════════════════════\n", 'header')
            self.stats_text.insert('end', f"  Elapsed Time:        {stats['elapsed_formatted']}\n", 'stat')
            self.stats_text.insert('end', f"  Wallets Checked:     {stats['wallets_checked']:,}\n", 'stat')
            self.stats_text.insert('end', f"  Addresses Checked:   {stats['addresses_checked']:,}\n", 'stat')
            self.stats_text.insert('end', f"  Wallets w/ Balance:  {stats['wallets_with_balance']:,}\n", 'found')
            self.stats_text.insert('end', f"  Wallets w/ Activity: {stats['wallets_with_activity']:,}\n", 'stat')
            self.stats_text.insert('end', f"  API Calls:           {stats['api_calls']:,}\n", 'stat')
            self.stats_text.insert('end', f"  API Failures:        {stats['api_failures']:,}\n", 'stat')
            self.stats_text.insert('end', f"  API Success Rate:    {stats['api_success_rate']:.1f}%\n", 'stat')
            self.stats_text.insert('end', f"  Wallets/Second:      {stats['wallets_per_second']:.2f}\n", 'stat')
            self.stats_text.insert('end', f"  Found Total:         {stats['found_count']:,}\n", 'found')
            self.stats_text.insert('end', "═══════════════════════════════════════════════\n", 'header')
            self.stats_text.configure(state='disabled')
        self.root.after(0, update)

    def _log_handler(self, message: str, level: str):
        tag = 'info'
        if 'ERROR' in level:
            tag = 'error'
        elif 'WARNING' in level:
            tag = 'warning'
        elif '🎉' in message:
            tag = 'found'
        self.log_queue.put((message, tag))

    def _start(self):
        chains = [c for c, v in self.chain_vars.items() if v.get()]
        if not chains: messagebox.showerror("Error", "Select at least one chain!"); return
        address_types = [a for a, v in self.addr_type_vars.items() if v.get()]
        if not address_types: messagebox.showerror("Error", "Select at least one address type!"); return
        
        method = self.method_var.get()
        mnemonic = self.mnemonic_var.get().strip()
        if mnemonic:
            self._log(f"[*] Checking single mnemonic: {mnemonic[:30]}...", 'header')
            threading.Thread(target=self._run_single_check, args=(mnemonic, chains, address_types), daemon=True).start()
            return

        if method == "vanity" and not self.vanity_var.get().strip():
            messagebox.showerror("Error", "Vanity method requires a prefix!"); return

        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.is_running = True

        self.hunter = WalletHunter(
            method=method, chains=chains, address_types=address_types,
            num_threads=self.threads_var.get(),
            proxy_file=self.proxy_file_var.get().strip() or None,
            proxy_type=self.proxy_type_var.get(),
            webhook_url=self.webhook_var.get().strip() or None,
            api_timeout=self.timeout_var.get(), max_retries=self.retries_var.get(),
            vanity_prefix=self.vanity_var.get().strip() or None,
            brain_passphrases=self.passphrase_file_var.get().strip() or None,
            stats_callback=self._stats_callback
        )
        threading.Thread(target=self._run_hunter, daemon=True).start()

    def _run_hunter(self):
        try: self.hunter.start()
        except Exception as e: self._log(f"[!] Fatal error: {e}", 'error')

    def _run_single_check(self, mnemonic: str, chains: List[str], address_types: List[str]):
        try:
            results = check_single_wallet(mnemonic, chains, address_types, self.proxy_file_var.get().strip() or None)
            for chain, chain_results in results.items():
                for addr_type, result in chain_results.items():
                    balance = result.get("balance_coin", 0)
                    has_activity = result.get("has_activity", False)
                    address = result.get("address", "")
                    if balance > 0: self._log(f"💰 FOUND! {chain} ({addr_type}): {address} — Balance: {balance:.8f}", 'found')
                    elif has_activity: self._log(f"📨 Activity! {chain} ({addr_type}): {address}", 'found')
                    else: self._log(f"   Empty: {chain} ({addr_type}): {address}", 'info')
        except Exception as e: self._log(f"[!] Error: {e}", 'error')

    def _stop(self):
        if self.hunter:
            self._log("[*] Stopping wallet hunter...", 'header')
            try:
                self.hunter.stop()
            except Exception as e:
                self._log(f"[!] Error stopping hunter: {e}", 'error')
            self.hunter = None
        self.start_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        self.is_running = False

class GUILogHandler(logging.Handler):
    def __init__(self, gui: WalletHunterGUI):
        super().__init__()
        self.gui = gui
    def emit(self, record):
        msg = self.format(record)
        level = record.levelname
        self.gui._log_handler(msg, level)

# ─── CLI Execution Logic ───────────────────────────────────────────────────

def clear():
    if os.name == 'nt':
        os.system("cls")
    else:
        os.system("clear")

def center(var: str, space: int = None):
    if not space:
        try:
            space = (os.get_terminal_size().columns - len(var.splitlines()[int(len(var.splitlines()) / 2)])) / 2
        except Exception:
            space = 10
    return "\n".join((' ' * int(space)) + v for v in var.splitlines())

def ui():
    clear() 
    font = """
                ▄▄▄▄   ▄▄▄█████▓ ▄████▄    █████▒▒█████   ██▀███   ▄████▄  ▓█████  ██▀███  
                ▓█████▄ ▓  ██▒ ▓▒▒██▀ ▀█  ▓██   ▒▒██▒  ██▒▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀ ▓██ ▒ ██▒
                ▒██▒ ▄██▒ ▓██░ ▒░▒▓█    ▄ ▒████ ░▒██░  ██▒▓██ ░▄█ ▒▒▓█    ▄ ▒███   ▓██ ░▄█ ▒
                ▒██░█▀  ░ ▓██▓ ░ ▒▓▓▄ ▄██▒░▓█▒  ░▒██   ██░▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄ ▒██▀▀█▄  
                ░▓█  ▀█▓  ▒██▒ ░ ▒ ▓███▀ ░░▒█░   ░ ████▓▒░░██▓ ▒██▒▒ ▓███▀ ░░▒████▒░██▓ ▒██▒
                ░▒▓███▀▒  ▒ ░░   ░ ░▒ ▒  ░ ▒ ░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░░ ▒▓ ░▒▓░
                ▒░▒   ░     ░      ░  ▒    ░       ░ ▒ ▒░   ░▒ ░ ▒░  ░  ▒    ░ ░  ░  ░▒ ░ ▒░
                ░    ░   ░      ░         ░ ░   ░ ░ ░ ▒    ░░   ░ ░           ░     ░░   ░ 
                ░               ░ ░                 ░ ░     ░     ░ ░         ░  ░   ░     
                    ░          ░                                 ░                        """
    faded = ''
    red = 0
    for line in font.splitlines():
        faded += (f"\033[38;2;{red};10;230m{line}\033[0m\n")
        if not red == 255:
            red += 10
            if red > 110:
                red = 255
    print(center(faded))
    print(center(f'{Fore.LIGHTYELLOW_EX}\ngithub.com/LizardX2 Version 2.0 | Telegram: @LizardX2\n{Fore.RESET}'))

def safe_print(msg: str):
    with print_lock:
        print(msg)

def record_result(address, balance, all_time_balance, seed, private_key, entropy, wif, success):
    filename = config_success if success else config_failed
    with file_lock:
        try:
            with open(filename, "a") as f:
                f.write(f"{address} | {balance} | {all_time_balance} | {seed} | {private_key} | {entropy} | {wif} \n")
        except Exception:
            pass

def cli_worker_loop(chain, addr_type, strength, language, passphrase, stop_event):
    generator = WalletGenerator()
    proxy_file = "proxy.txt" if os.path.exists("proxy.txt") else None
    checker = BlockchainChecker(ProxyManager(proxy_file))
    
    while not stop_event.is_set():
        try:
            mnemonic, entropy_hex = BIP39Wordlist.generate_mnemonic_with_strength_and_entropy(strength, language)
            mnemonic_str = " ".join(mnemonic)
            seed = BIP39Wordlist.mnemonic_to_seed(mnemonic, passphrase)
            master_key, master_chain_code = BIP32Derivation.master_key_from_seed(seed)
            
            config = CHAIN_CONFIG.get(chain)
            path = config["derivation_paths"].get(addr_type)
            priv_key, _ = BIP32Derivation.derive_path(master_key, master_chain_code, path)
            pubkey = BIP32Derivation.private_to_public_key(priv_key, compressed=True)
            
            address = generator._get_address(chain, addr_type, pubkey)
            wif = AddressGenerator.private_to_wif(priv_key, chain)
            
            res = checker.check_address(address, chain)
            if res:
                balance_coin = res.get("balance_coin", 0.0)
                received_coin = res.get("received_coin", 0.0)
                has_activity = res.get("has_activity", False)
            else:
                balance_coin = 0.0
                received_coin = 0.0
                has_activity = False
                
            now_time = datetime.now()
            current = now_time.strftime("%H:%M:%S")
            
            balance_str = f"{balance_coin:.8f}"
            rec_str = f"{received_coin:.8f}"
            priv_hex = priv_key.hex()
            
            print_line = (
                f"{Fore.LIGHTBLACK_EX}[{current}]{Fore.RESET} "
                f"{Fore.YELLOW}{address}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.LIGHTGREEN_EX}BAL: {balance_str} {chain}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.LIGHTWHITE_EX}SEED: {mnemonic_str}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.LIGHTRED_EX}PRIV: {priv_hex}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.BLUE}{strength}{Fore.RESET}"
            )
            safe_print(print_line)
            
            success = (balance_coin > 0.0) or has_activity
            record_result(address, balance_str, rec_str, mnemonic_str, priv_hex, entropy_hex, wif, success)
            
        except Exception:
            pass

def cli_checker_worker_loop(chain, addr_type, passphrase, q, stop_event):
    generator = WalletGenerator()
    proxy_file = "proxy.txt" if os.path.exists("proxy.txt") else None
    checker = BlockchainChecker(ProxyManager(proxy_file))
    
    while not stop_event.is_set():
        try:
            mnemonic_str = q.get_nowait()
        except queue.Empty:
            break
            
        try:
            mnemonic = mnemonic_str.strip().split()
            if len(mnemonic) not in (12, 15, 18, 21, 24):
                safe_print(f"{Fore.RED}[x] Invalid mnemonic format: '{mnemonic_str}'{Fore.RESET}")
                q.task_done()
                continue
                
            seed = BIP39Wordlist.mnemonic_to_seed(mnemonic, passphrase)
            master_key, master_chain_code = BIP32Derivation.master_key_from_seed(seed)
            
            config = CHAIN_CONFIG.get(chain)
            path = config["derivation_paths"].get(addr_type)
            priv_key, _ = BIP32Derivation.derive_path(master_key, master_chain_code, path)
            pubkey = BIP32Derivation.private_to_public_key(priv_key, compressed=True)
            
            address = generator._get_address(chain, addr_type, pubkey)
            wif = AddressGenerator.private_to_wif(priv_key, chain)
            
            res = checker.check_address(address, chain)
            if res:
                balance_coin = res.get("balance_coin", 0.0)
                received_coin = res.get("received_coin", 0.0)
                has_activity = res.get("has_activity", False)
            else:
                balance_coin = 0.0
                received_coin = 0.0
                has_activity = False
                
            now_time = datetime.now()
            current = now_time.strftime("%H:%M:%S")
            
            balance_str = f"{balance_coin:.8f}"
            rec_str = f"{received_coin:.8f}"
            priv_hex = priv_key.hex()
            
            print_line = (
                f"{Fore.LIGHTBLACK_EX}[{current}]{Fore.RESET} "
                f"{Fore.YELLOW}{address}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.LIGHTGREEN_EX}BAL: {balance_str} {chain}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.LIGHTWHITE_EX}SEED: {mnemonic_str}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} "
                f"{Fore.LIGHTRED_EX}PRIV: {priv_hex}{Fore.RESET}"
            )
            safe_print(print_line)
            
            success = (balance_coin > 0.0) or has_activity
            record_result(address, balance_str, rec_str, mnemonic_str, priv_hex, "", wif, success)
            
        except Exception:
            pass
        finally:
            q.task_done()

def map_address_type(addr_type_str: str) -> str:
    addr_type_str = addr_type_str.lower()
    if addr_type_str == "p2pkh":
        return "legacy"
    elif addr_type_str in ("p2sh", "p2wpkh_in_p2sh", "p2wsh_in_p2sh"):
        return "segwit"
    elif addr_type_str in ("p2wpkh", "p2wsh"):
        return "bech32"
    return "legacy"

def run_cli_hunter(mode_name: str):
    print("\n")
    print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Saving failed seeds on >> {Fore.LIGHTYELLOW_EX}{config_failed}{Fore.RESET}")
    print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Saving successful seeds on >> {Fore.LIGHTYELLOW_EX}{config_success}{Fore.RESET}")
    
    q = queue.Queue()
    mnemonics_count = 0
    
    if mode_name == "checker":
        print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Checking from file >> {Fore.LIGHTYELLOW_EX}{c_config_file}{Fore.RESET}")
        if not os.path.exists(c_config_file):
            print(f"{Fore.RED}[x] Error: file '{c_config_file}' not found! Please create it and add mnemonics to check.{Fore.RESET}")
            sys.exit(1)
        with open(c_config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    q.put(line)
                    mnemonics_count += 1
        if mnemonics_count == 0:
            print(f"{Fore.RED}[x] Error: '{c_config_file}' contains no mnemonics!{Fore.RESET}")
            sys.exit(1)
        print(f"{Fore.GREEN}[*] Loaded {mnemonics_count} mnemonics from '{c_config_file}' for checking.{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Bruteforcing random seeds...{Fore.RESET}")
        
    print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Type of addresses >> {Fore.LIGHTYELLOW_EX}{config_address}{Fore.RESET}")
    if mode_name != "checker":
        print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Language >> {Fore.LIGHTYELLOW_EX}{b_config_language}{Fore.RESET}")
        print(f"{Fore.YELLOW}[!]{Fore.RESET} {Fore.LIGHTWHITE_EX}Strength >> {Fore.LIGHTYELLOW_EX}{b_config_strenght}{Fore.RESET}")
    
    # Prompt for threads count
    try:
        threads_input = input(f"\n{Fore.YELLOW}[?]{Fore.RESET} {Fore.LIGHTWHITE_EX}Enter number of worker threads (default: 16) > {Fore.RESET}").strip()
        num_threads = int(threads_input) if threads_input else 16
    except ValueError:
        num_threads = 16
        
    print(f"{Fore.GREEN}[*] Starting with {num_threads} worker threads... Press Ctrl+C to stop.{Fore.RESET}\n")
    time.sleep(1.5)

    mapped_addr = map_address_type(config_address)
    stop_event = threading.Event()
    threads = []
    
    if mode_name == "checker":
        for _ in range(min(num_threads, mnemonics_count)):
            t = threading.Thread(
                target=cli_checker_worker_loop,
                args=("BTC", mapped_addr, b_config_passphere, q, stop_event),
                daemon=True
            )
            t.start()
            threads.append(t)
            
        try:
            while not q.empty() and not stop_event.is_set():
                time.sleep(0.5)
            q.join()
            print(f"\n{Fore.GREEN}[+] Finished checking all loaded mnemonics from '{c_config_file}'.{Fore.RESET}")
            sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopping threads...{Fore.RESET}")
            stop_event.set()
            sys.exit(0)
    else:
        for _ in range(num_threads):
            t = threading.Thread(
                target=cli_worker_loop,
                args=("BTC", mapped_addr, b_config_strenght, b_config_language, b_config_passphere, stop_event),
                daemon=True
            )
            t.start()
            threads.append(t)
            
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopping threads...{Fore.RESET}")
            stop_event.set()
            for t in threads:
                t.join(timeout=1.0)
            print(f"{Fore.GREEN}[+] Stopped.{Fore.RESET}")
            sys.exit(0)

# ─── Main Switchboard ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Multi-Chain Wallet Hunter & Checker")
    parser.add_argument("--cli", action="store_true", help="Force CLI mode")
    parser.add_argument("--gui", action="store_true", help="Force GUI mode")
    args = parser.parse_args()

    if args.gui:
        try:
            run_gui()
        except ImportError as e:
            print(f"\n{Fore.RED}[x] Error: {e}{Fore.RESET}")
            print("To run the GUI, please install Tkinter using your package manager:")
            print("  - Termux:         pkg install python-tkinter")
            print("  - Debian/Ubuntu:  sudo apt install python3-tk")
            print("  - CentOS/RHEL:    sudo yum install python3-tkinter")
            print("  - macOS:          brew install python-tk")
            sys.exit(1)
        return
    elif args.cli:
        run_cli()
        return

    # Check if DISPLAY env var is present (suggests GUI support) and try to run GUI
    if os.environ.get("DISPLAY") or os.name == "nt":
        try:
            run_gui()
            return
        except Exception:
            pass
            
    run_cli()

def run_gui():
    if not HAS_TKINTER:
        raise ImportError("Tkinter is not installed on this system.")
    root = tk.Tk()
    app = WalletHunterGUI(root)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    handler = GUILogHandler(app)
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
    logging.getLogger().addHandler(handler)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        if app.hunter:
            app.hunter.stop()
        sys.exit(0)

def run_cli():
    ui()
    choice = input(f"{Fore.YELLOW}[?]{Fore.RESET} {Fore.LIGHTWHITE_EX}Make a choice between Checker, Bruteforcer, and GUI [C] - [B] - [G] > {Fore.RESET}").strip().lower()
    
    if choice == "g":
        try:
            run_gui()
        except ImportError as e:
            print(f"\n{Fore.RED}[x] Error: {e}{Fore.RESET}")
            print("To run the GUI, please install Tkinter using your package manager:")
            print("  - Termux:         pkg install python-tkinter")
            print("  - Debian/Ubuntu:  sudo apt install python3-tk")
            print("  - CentOS/RHEL:    sudo yum install python3-tkinter")
            print("  - macOS:          brew install python-tk")
            sys.exit(1)
    elif choice == "b":
        run_cli_hunter("bruteforcer")
    elif choice == "c":
        run_cli_hunter("checker")
    else:
        print(f"{Fore.RED}[x] Invalid choice! Aborting...{Fore.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
