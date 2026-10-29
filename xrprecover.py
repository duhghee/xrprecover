#!/usr/bin/env python3
# Install: python -m pip install mnemonic bip-utils coincurve
"""
Advanced XRP seed-recovery tool (12-word BIP-39 only).

Derivation: BIP-39 (empty passphrase) -> BIP-32 secp256k1 -> XRP classic address
at m/44'/144'/0'/0/0. Only *classic* r-addresses are accepted; X-addresses are
rejected up front.

Modes 1-15 extend the original menu; see --help / the interactive menu.
"""

import argparse
import hashlib
import hmac
import itertools
import json
import math
import multiprocessing as mp
import os
import re
import signal
import sys
import time
import unicodedata
from collections import Counter
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from mnemonic import Mnemonic
from coincurve import PublicKey
from bip_utils import Bip44, Bip44Coins, Bip44Changes, XrpAddrDecoder, XrpAddrEncoder

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
MNEMO = Mnemonic("english")
WORDLIST = tuple(MNEMO.wordlist)
WORD_INDEX = {w: i for i, w in enumerate(WORDLIST)}
SUPPORTED_LENGTHS = {12}
XRP_PATH_INDICES = (0x8000002C, 0x80000090, 0x80000000, 0, 0)
XRP_DERIVATION_PATH = "m/44'/144'/0'/0/0"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DEFAULT_PROCESSES = os.cpu_count() or 1
DEFAULT_BATCH_SIZE = 1024
MODE3_LINES_PER_FILE = 10_000_000

PBKDF2_BACKEND = "auto"
DISTRIBUTED_WORKER = None
_NATIVE_ENGINE = None
_NATIVE_CHECKED = False
_WORKER_CONFIG = None
_WORKER_NATIVE = None


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def clear_screen():
    # ANSI is portable and avoids spawning a shell (unlike os.system).
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def is_classic_xrp_address(addr):
    """True only for a valid classic r-address (never an X-address)."""
    if not isinstance(addr, str):
        return False
    if not (25 <= len(addr) <= 35) or addr[0] != "r":
        return False
    try:
        XrpAddrDecoder.DecodeAddr(addr)
        return True
    except (ValueError, TypeError):
        return False


def parse_mnemonic_input(raw_text):
    """Normalize pasted text (NFKC, strip zero-width chars) into words."""
    normalized = unicodedata.normalize("NFKC", raw_text)
    for invisible in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        normalized = normalized.replace(invisible, " ")
    return normalized.casefold().split()


def prepare_words(words):
    """Map words to BIP-39 indices. Reject unknown words; never fall back to 0."""
    out = []
    for word in words:
        idx = WORD_INDEX.get(word)
        if idx is None:
            print(f"\nUnknown BIP-39 word: {word!r}")
            return None
        out.append(idx)
    return tuple(out)


def pack_indices(indices):
    value = 0
    for index in indices:
        value = (value << 11) | index
    return value


def checksum_valid(value):
    """12 words = 128 entropy bits + 4 checksum bits."""
    return (sha256((value >> 4).to_bytes(16, "big")).digest()[0] >> 4) == (value & 15)


def unique_permutations(indices):
    """Stream distinct arrangements (handles duplicate words)."""
    counts = Counter(indices)
    if len(counts) == len(indices):
        yield from itertools.permutations(indices)
        return
    keys = tuple(sorted(counts))
    result = [0] * len(indices)

    def visit(depth):
        if depth == len(result):
            yield tuple(result)
            return
        for key in keys:
            if counts[key]:
                counts[key] -= 1
                result[depth] = key
                yield from visit(depth + 1)
                counts[key] += 1

    yield from visit(0)


def print_progress_bar(fraction):
    bar_length = 30
    filled = int(bar_length * fraction)
    return "[" + "█" * filled + "░" * (bar_length - filled) + f"] {fraction * 100:.1f}%"


# --------------------------------------------------------------------------
# XRP derivation (optimized: no EC mult on the three hardened steps)
# --------------------------------------------------------------------------
def _derive_xrp_from_seed(seed, seed_phrase):
    digest = hmac.digest(b"Bitcoin seed", seed, "sha512")
    key = int.from_bytes(digest[:32], "big")
    chain = digest[32:]
    if not 0 < key < SECP256K1_ORDER:
        return _reference_xrp_address(seed_phrase)
    for index in XRP_PATH_INDICES:
        secret = key.to_bytes(32, "big")
        if index & 0x80000000:
            data = b"\x00" + secret          # hardened: zero-prefix, NO EC mult
        else:
            data = PublicKey.from_valid_secret(secret).format(compressed=True)
        digest = hmac.digest(chain, data + index.to_bytes(4, "big"), "sha512")
        tweak = int.from_bytes(digest[:32], "big")
        key = (key + tweak) % SECP256K1_ORDER
        if tweak >= SECP256K1_ORDER or key == 0:
            return _reference_xrp_address(seed_phrase)
        chain = digest[32:]
    public = PublicKey.from_valid_secret(key.to_bytes(32, "big")).format(compressed=True)
    return XrpAddrEncoder.EncodeKey(public)


def _reference_xrp_address(seed_phrase):
    seed = MNEMO.to_seed(seed_phrase, passphrase="")
    wallet = (Bip44.FromSeed(seed, Bip44Coins.RIPPLE)
              .Purpose().Coin().Account(0)
              .Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    return wallet.PublicKey().ToAddress()


def derive_xrp_address(seed_phrase):
    """Derive a secp256k1 XRP classic address from a 12-word BIP-39 mnemonic."""
    words = seed_phrase.split()
    if len(words) != 12:
        raise ValueError("Seed phrase must contain exactly 12 words")
    if not MNEMO.check(seed_phrase):
        raise ValueError("Invalid BIP-39 seed phrase")
    seed = MNEMO.to_seed(seed_phrase, passphrase="")
    return _derive_xrp_from_seed(seed, seed_phrase)


def validate_xrp_address(seed_phrase, target_address):
    # XRP classic addresses are case-sensitive.
    return derive_xrp_address(seed_phrase) == target_address


# --------------------------------------------------------------------------
# Progress + native backend
# --------------------------------------------------------------------------
class ProgressTracker:
    def __init__(self, mode_name, total):
        self.start_time = time.monotonic()
        self.last_update = self.start_time
        self.processed = 0
        self.total = total
        self.mode_name = mode_name
        print(f"\n{mode_name}: {total:,} candidates to check")
        self.render()

    @staticmethod
    def format_eta(seconds):
        if seconds is None:
            return "estimating..."
        seconds = math.ceil(seconds)
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        return (f"{days}d " if days else "") + f"{hours:02}:{minutes:02}:{seconds:02}"

    def render(self):
        now = time.monotonic()
        elapsed = now - self.start_time
        speed = self.processed / elapsed if elapsed > 0 else 0
        remaining = max(0, self.total - self.processed)
        eta = 0 if remaining == 0 else (remaining / speed if speed > 0 else None)
        fraction = self.processed / self.total if self.total else 1
        print(f"\r[{datetime.now().strftime('%H:%M:%S')}] {self.mode_name} | "
              f"Total: {self.total:,} | Checked: {self.processed:,} | "
              f"Remaining: {remaining:,} | Speed: {speed:,.0f}/sec | "
              f"ETA: {self.format_eta(eta)} | {print_progress_bar(fraction)}",
              end="", flush=True)
        self.last_update = now

    def update(self, count=1):
        self.processed += count
        if time.monotonic() - self.last_update >= 2:
            self.render()

    def finish(self, interrupted=False, stopped_early=False):
        self.render()
        if interrupted:
            print("\nSearch interrupted.")
        elif stopped_early:
            print("\nAddress match found; search stopped early.")
        else:
            print("\nSearch complete.")


def optional_native_engine():
    global _NATIVE_ENGINE, _NATIVE_CHECKED
    if PBKDF2_BACKEND == "reference":
        return None
    if _NATIVE_CHECKED:
        return _NATIVE_ENGINE
    _NATIVE_CHECKED = True
    folder = Path(__file__).resolve().parent
    config_path = folder / "pbkdf2_backend.json"
    if not config_path.exists():
        return None
    try:
        config = json.loads(config_path.read_text())
        if not (config.get("enabled") and config.get("verified")
                and config.get("speedup", 0) >= 1.10):
            return None
        library = folder / "libpbkdf2_avx2.so"
        if hashlib.sha256(library.read_bytes()).hexdigest() != config.get("library_sha256"):
            raise RuntimeError("library changed since benchmark; rerun verification")
        from pbkdf2_native import NativePBKDF2
        _NATIVE_ENGINE = NativePBKDF2(library)
    except (OSError, ValueError, RuntimeError, ImportError) as error:
        print(f"Native PBKDF2 unavailable: {error}. Using reference backend.")
    return _NATIVE_ENGINE


def initialize_worker(config, ignore_interrupt=True):
    global _WORKER_CONFIG, _WORKER_NATIVE
    _WORKER_CONFIG = config
    _WORKER_NATIVE = optional_native_engine() if config.get("native") else None
    if ignore_interrupt:
        signal.signal(signal.SIGINT, signal.SIG_IGN)


# --------------------------------------------------------------------------
# Per-candidate evaluation (runs in worker processes)
# --------------------------------------------------------------------------
def process_batch(batch):
    config = _WORKER_CONFIG
    mode = config["mode"]
    valid = []

    for candidate in batch:
        if mode == 1:
            position, replacement = candidate
            shift = (11 - position) * 11
            value = (config["base"] & ~(2047 << shift)) | (replacement << shift)
            if config["invalid"] - {position} or not checksum_valid(value):
                continue
            words = config["words"].copy()
            words[position] = WORDLIST[replacement]
            phrase = " ".join(words)
            valid.append((phrase, dict(position=position + 1,
                original=config["words"][position], replacement=words[position],
                phrase=phrase)))
        elif mode in (14, 15):
            indices = candidate
            if not checksum_valid(pack_indices(indices)):
                continue
            words = [WORDLIST[i] for i in indices]
            phrase = " ".join(words)
            valid.append((phrase, dict(phrase=phrase, address=config["target"])))
        elif mode == 10:
            first, second, first_word, second_word = candidate
            fs, ss = (11 - first) * 11, (11 - second) * 11
            clear = (2047 << fs) | (2047 << ss)
            value = ((config["base"] & ~clear) | (first_word << fs) | (second_word << ss))
            if config["invalid"] - {first, second} or not checksum_valid(value):
                continue
            words = config["words"].copy()
            words[first] = WORDLIST[first_word]
            words[second] = WORDLIST[second_word]
            phrase = " ".join(words)
            valid.append((phrase, dict(
                positions=[first + 1, second + 1],
                originals=[config["words"][first], config["words"][second]],
                replacements=[words[first], words[second]],
                phrase=phrase, address=config["target"])))
        elif mode == 11:
            first, second, third, fw, sw, tw = candidate
            fs, ss, ts = (11 - first) * 11, (11 - second) * 11, (11 - third) * 11
            clear = (2047 << fs) | (2047 << ss) | (2047 << ts)
            value = ((config["base"] & ~clear) | (fw << fs) | (sw << ss) | (tw << ts))
            if config["invalid"] - {first, second, third} or not checksum_valid(value):
                continue
            words = config["words"].copy()
            words[first] = WORDLIST[fw]
            words[second] = WORDLIST[sw]
            words[third] = WORDLIST[tw]
            phrase = " ".join(words)
            valid.append((phrase, dict(
                positions=[first + 1, second + 1, third + 1],
                originals=[config["words"][first], config["words"][second],
                           config["words"][third]],
                replacements=[words[first], words[second], words[third]],
                phrase=phrase, address=config["target"])))
        elif mode == 8:
            value = config["base"]
            for shift, replacement in zip(config["shifts"], candidate):
                value |= replacement << shift
            if not checksum_valid(value):
                continue
            words = config["words"].copy()
            for position, replacement in zip(config["positions"], candidate):
                words[position] = WORDLIST[replacement]
            phrase = " ".join(words)
            valid.append((phrase, dict(
                phrase=phrase,
                positions=[p + 1 for p in config["positions"]],
                replacements=[words[p] for p in config["positions"]],
                address=config["target"])))
        else:
            value = pack_indices(candidate)
            if mode in (2, 3, 13):
                value |= config["prefix"]
            if not checksum_valid(value):
                continue
            words = [WORDLIST[i] for i in candidate]
            if mode in (2, 3, 13):
                words = config["words"] + words
            if mode in (3, 6, 12, 13) and len(set(words)) != 12:
                continue
            phrase = " ".join(words)
            valid.append((phrase, dict(phrase=phrase, address=config["target"])
                          if mode in (9, 13) else None))

    if mode in (3, 6, 12):
        return len(batch), [phrase for phrase, _ in valid]

    phrases = [phrase for phrase, _ in valid]
    seeds = (_WORKER_NATIVE.derive(phrases) if _WORKER_NATIVE
             else [MNEMO.to_seed(p, passphrase="") for p in phrases])
    results = []
    for (phrase, metadata), seed in zip(valid, seeds):
        address = _derive_xrp_from_seed(seed, phrase)
        if mode in (1, 8, 9, 10, 11, 13, 14, 15):
            if address == config["target"]:
                results.append(metadata)
        elif address.endswith(config["pattern"]):
            results.append(dict(phrase=phrase, address=address))
    return len(batch), results


# --------------------------------------------------------------------------
# Search driver
# --------------------------------------------------------------------------
def candidate_batches(candidates, batch_size):
    iterator = iter(candidates)
    while True:
        batch = tuple(itertools.islice(iterator, batch_size))
        if not batch:
            return
        yield batch


def run_search(name, total, candidates, config, processes=None,
               batch_size=DEFAULT_BATCH_SIZE, on_match=None, collect_results=True,
               preview_limit=None, stop_on_first=False):
    processes = DEFAULT_PROCESSES if processes is None else processes
    if processes < 1 or batch_size < 1:
        raise ValueError("Processes and batch size must be positive")

    config = dict(config)
    needs_native = config["mode"] in (1, 2, 8, 9, 10, 11, 13, 14, 15)
    config["native"] = needs_native and optional_native_engine() is not None
    if needs_native:
        print("PBKDF2 backend: "
              + ("AVX2 (verified benchmark)" if config["native"] else "reference"))

    batches = candidate_batches(candidates, batch_size)
    if DISTRIBUTED_WORKER is not None:
        worker_id, worker_count = DISTRIBUTED_WORKER
        batches = itertools.islice(batches, worker_id - 1, None, worker_count)
        batch_count = (total + batch_size - 1) // batch_size
        assigned = max(0, (batch_count - worker_id) // worker_count + 1)
        total = min(total, assigned * batch_size)
        print(f"Distributed worker {worker_id}/{worker_count}: {assigned:,} batches assigned")

    workers = min(processes, max(1, math.ceil(total / batch_size)))
    print(f"\nMultiprocessing workers: {workers} | Batch size: {batch_size:,}")
    tracker = ProgressTracker(f"Mode {config['mode']}", total)
    results = []
    match_count = 0
    preview_count = 0
    interrupted = False
    stopped_early = False

    def consume(result):
        nonlocal match_count, preview_count
        count, matches = result
        for match in matches:
            match_count += 1
            if on_match is not None:
                on_match(match)
            if preview_limit is None or preview_count < preview_limit:
                if isinstance(match, str):
                    print("\n" + match)
                else:
                    print(f"\nMatch found!\nSeed: {match['phrase']}")
                    if "address" in match:
                        print(f"Address: {match['address']}")
                        if "originals" in match:
                            changes = ", ".join(
                                f"{pos}: {old} -> {new}"
                                for pos, old, new in zip(match["positions"],
                                                         match["originals"],
                                                         match["replacements"]))
                            print("Changed positions: " + changes)
                        elif "positions" in match:
                            print("Missing positions: " + ", ".join(map(str, match["positions"])))
                    else:
                        print(f"Position {match['position']}: "
                              f"{match['original']} -> {match['replacement']}")
                preview_count += 1
        if collect_results:
            results.extend(matches)
        tracker.update(count)
        return bool(matches)

    pool = None
    try:
        if workers == 1:
            initialize_worker(config, ignore_interrupt=False)
            for batch in batches:
                if consume(process_batch(batch)) and stop_on_first:
                    stopped_early = True
                    break
        else:
            def _gen():
                for batch in batches:
                    yield batch
            with mp.get_context("spawn").Pool(workers, initialize_worker, (config,)) as pool:
                for result in pool.imap_unordered(process_batch, _gen(), chunksize=1):
                    if consume(result) and stop_on_first:
                        stopped_early = True
                        pool.terminate()
                        break
                if not stopped_early:
                    pool.close()
                pool.join()
                pool = None
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if pool is not None:
            pool.terminate()
            pool.join()
        tracker.finish(interrupted, stopped_early)

    if preview_limit is not None and preview_limit > 0 and match_count > preview_count:
        print(f"\n{match_count - preview_count:,} additional matches not printed to the terminal.")
    return results if collect_results else match_count


# --------------------------------------------------------------------------
# Mode implementations
# --------------------------------------------------------------------------
def scan_positions_for_address(seed_words, target_address, wordlist,
                               processes=None, batch_size=DEFAULT_BATCH_SIZE):
    if len(seed_words) != 12:
        print("\nSeed phrase must contain exactly 12 words.")
        return []
    if not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address (expected an r-address, not X...).")
        return []
    pool_words = tuple(dict.fromkeys(wordlist))
    replacements = prepare_words(pool_words)
    if replacements is None:
        return []
    indices = [WORD_INDEX.get(word, 0) for word in seed_words]
    invalid = {i for i, word in enumerate(seed_words) if word not in WORD_INDEX}
    total = sum(len(pool_words) - (word in pool_words) for word in seed_words)
    candidates = ((position, index) for position in range(12)
                  for word, index in zip(pool_words, replacements)
                  if word != seed_words[position])
    config = dict(mode=1, words=seed_words, base=pack_indices(indices),
                  invalid=invalid, target=target_address)
    return run_search("Position Scanner", total, candidates, config,
                      processes, batch_size)


def scan_permuted_one_wrong_word(seed_words, target_address, wordlist,
                                 processes=None, batch_size=DEFAULT_BATCH_SIZE):
    """Try replacing exactly one word, then every ordering of the 12 words."""
    if len(seed_words) != 12:
        print("\\nSeed phrase must contain exactly 12 words.")
        return []
    if not is_classic_xrp_address(target_address):
        print("\\nInvalid XRP classic address.")
        return []
    if any(word not in WORD_INDEX for word in seed_words):
        print("\\nAll 12 input words must belong to the BIP-39 wordlist.")
        return []
    if len(set(seed_words)) != 12:
        print("\\nMode 14 requires 12 distinct input words.")
        return []
    pool = tuple(dict.fromkeys(wordlist))
    replacements = prepare_words(pool)
    if replacements is None:
        return []
    original = tuple(WORD_INDEX[word] for word in seed_words)
    original_set = set(original)
    # Replacing an existing word would leave a duplicate, so only use new words.
    new_indices = tuple(index for index in replacements if index not in original_set)
    total = len(new_indices) * 12 * math.factorial(12)
    def candidates():
        for replacement in new_indices:
            for removed in range(12):
                modified = original[:removed] + original[removed + 1:] + (replacement,)
                yield from itertools.permutations(modified)
    print(f"Mode 14: {total:,} permutations (one replacement, all 12 positions).")
    return run_search("Permuted One-Word Scanner", total, candidates(),
                      dict(mode=14, target=target_address),
                      processes, batch_size, stop_on_first=True)


def scan_permuted_two_wrong_words(seed_words, target_address, wordlist,
                                  processes=None, batch_size=DEFAULT_BATCH_SIZE):
    """Replace exactly two of twelve distinct words, then permute all positions.

    Each resulting set of 12 words is enumerated once. Input ordering is not
    assumed to be correct. Matches are validated against the target address.
    """
    if len(seed_words) != 12:
        print("\nSeed phrase must contain exactly 12 words.")
        return []
    if not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address.")
        return []
    if any(word not in WORD_INDEX for word in seed_words):
        print("\nAll 12 input words must belong to the BIP-39 wordlist.")
        return []
    if len(set(seed_words)) != 12:
        print("\nMode 15 requires 12 distinct input words.")
        return []
    pool_words = tuple(dict.fromkeys(wordlist))
    indices = prepare_words(pool_words)
    if indices is None:
        return []
    original = tuple(WORD_INDEX[word] for word in seed_words)
    original_set = set(original)
    # Two novel, distinct replacements ensure exactly two changed words.
    replacement_indices = tuple(i for i in indices if i not in original_set)
    if len(replacement_indices) < 2:
        print("\nNeed at least two replacement words absent from the input.")
        return []
    total = (math.comb(12, 2) * math.comb(len(replacement_indices), 2)
             * math.factorial(12))

    def candidates():
        for removed in itertools.combinations(range(12), 2):
            retained = tuple(v for pos, v in enumerate(original) if pos not in removed)
            for replacements in itertools.combinations(replacement_indices, 2):
                yield from itertools.permutations(retained + replacements)

    print(f"\nMode 15: {total:,} candidates (2 replaced words; all 12 positions permuted).")
    print("WARNING: Full exhaustive searches are generally computationally infeasible.")
    return run_search("Permuted Two-Word Scanner", total, candidates(),
                      dict(mode=15, target=target_address),
                      processes, batch_size, stop_on_first=True)


def scan_two_positions_for_address(seed_words, target_address, wordlist,
                                   processes=None, batch_size=DEFAULT_BATCH_SIZE):
    if len(seed_words) != 12:
        print("\nSeed phrase must contain exactly 12 words.")
        return []
    if not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address (expected an r-address, not X...).")
        return []
    pool_words = tuple(dict.fromkeys(wordlist))
    replacements = prepare_words(pool_words)
    if replacements is None or not replacements:
        return []
    indices = [WORD_INDEX.get(word, 0) for word in seed_words]
    invalid = {p for p, w in enumerate(seed_words) if w not in WORD_INDEX}
    if len(invalid) > 2:
        print("\nMore than two words are not in the BIP-39 word list.")
        return []
    options = tuple(tuple(index for word, index in zip(pool_words, replacements)
                          if word != original) for original in seed_words)
    pairs = tuple((a, b) for a, b in itertools.combinations(range(12), 2)
                  if invalid.issubset((a, b)))
    total = sum(len(options[a]) * len(options[b]) for a, b in pairs)
    if not total:
        print("\nNo replacement candidates are available.")
        return []

    def candidates():
        for a, b in pairs:
            for wa, wb in itertools.product(options[a], options[b]):
                yield (a, b, wa, wb)

    print("\nChecking every pair of positions, changing BOTH words in each pair.")
    print("The other 10 words keep their original positions and spelling.")
    if total > 100_000_000:
        print("Warning: this is a very large search; a full scan may take a long time.")
    config = dict(mode=10, words=list(seed_words), base=pack_indices(indices),
                  invalid=invalid, target=target_address)
    return run_search("Two Wrong Words Address Scan", total, candidates(), config,
                      processes, batch_size, stop_on_first=True)


def scan_three_positions_for_address(seed_words, target_address, wordlist,
                                     processes=None, batch_size=DEFAULT_BATCH_SIZE):
    if len(seed_words) != 12:
        print("\nSeed phrase must contain exactly 12 words.")
        return []
    if not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address (expected an r-address, not X...).")
        return []
    pool_words = tuple(dict.fromkeys(wordlist))
    replacements = prepare_words(pool_words)
    if replacements is None or not replacements:
        return []
    indices = [WORD_INDEX.get(word, 0) for word in seed_words]
    invalid = {p for p, w in enumerate(seed_words) if w not in WORD_INDEX}
    if len(invalid) > 3:
        print("\nMore than three words are not in the BIP-39 word list.")
        return []
    options = tuple(tuple(index for word, index in zip(pool_words, replacements)
                          if word != original) for original in seed_words)
    triples = tuple(p for p in itertools.combinations(range(12), 3)
                    if invalid.issubset(p))
    total = sum(math.prod(len(options[p]) for p in pos) for pos in triples)
    if not total:
        print("\nNo replacement candidates are available.")
        return []

    def candidates():
        for a, b, c in triples:
            for wa, wb, wc in itertools.product(options[a], options[b], options[c]):
                yield (a, b, c, wa, wb, wc)

    print("\nChecking every triple of positions, changing ALL THREE words in each triple.")
    print("The other 9 words keep their original positions and spelling.")
    if total > 100_000_000:
        print("Warning: this is a massive search; using all 2,048 BIP-39 words may "
              "require impractically long runtimes.")
    config = dict(mode=11, words=list(seed_words), base=pack_indices(indices),
                  invalid=invalid, target=target_address)
    return run_search("Three Wrong Words Address Scan", total, candidates(), config,
                      processes, batch_size, stop_on_first=True)


def recover_missing_positions(seed_words, target_address, wordlist,
                              processes=None, batch_size=DEFAULT_BATCH_SIZE):
    if len(seed_words) != 12:
        print(f"\nExpected exactly 12 positions; received {len(seed_words)}.")
        return []
    seed_words = list(seed_words)
    positions = tuple(i for i, w in enumerate(seed_words) if w == "?")
    if not 1 <= len(positions) <= 4:
        print("\nUse '?' for 1 to 4 missing words (one '?' per missing position).")
        return []
    if prepare_words([w for w in seed_words if w != "?"]) is None:
        return []
    if not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address (expected an r-address, not X...).")
        return []
    candidate_indices = prepare_words(tuple(wordlist))
    if candidate_indices is None or not candidate_indices:
        return []
    base = pack_indices([WORD_INDEX.get(w, 0) for w in seed_words])
    shifts = tuple((11 - p) * 11 for p in positions)
    total = len(candidate_indices) ** len(positions)
    print(f"\nMissing word positions (1-12): {', '.join(str(p + 1) for p in positions)}")
    print("Known words stay in place. Searching all ordered missing-word combinations.")
    if len(positions) >= 3 and len(candidate_indices) == 2048:
        print("Note: 3-4 missing words can require extremely long search times.")
    config = dict(mode=8, words=seed_words, base=base, shifts=shifts,
                  positions=positions, target=target_address)
    return run_search("Missing Positions Address Scan", total,
                      itertools.product(candidate_indices, repeat=len(positions)),
                      config, processes, batch_size, stop_on_first=True)


def load_tokenlist(path):
    """Read tokenlist.py syntax: '^N^word' pins a row; bare rows permute."""
    path = Path(path).expanduser()
    fixed = {}
    floating = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                tokens = line.split()
                anchored = [t.startswith("^") for t in tokens]
                if any(anchored) and not all(anchored):
                    raise ValueError(f"Line {line_number}: cannot mix anchored/unanchored tokens")
                words, position = [], None
                for token in tokens:
                    token = token.casefold()
                    if anchored[0]:
                        match = re.fullmatch(r"\^(\d{1,2})\^([a-z]+)", token)
                        if match is None:
                            raise ValueError(f"Line {line_number}: invalid anchored token {token!r}")
                        pos = int(match.group(1))
                        if not 1 <= pos <= 12:
                            raise ValueError(f"Line {line_number}: position {pos} must be 1-12")
                        if position is not None and pos != position:
                            raise ValueError(f"Line {line_number}: all anchors must use one position")
                        position = pos
                        word = match.group(2)
                    else:
                        word = token
                    if word not in WORD_INDEX:
                        raise ValueError(f"Line {line_number}: unknown BIP-39 word {word!r}")
                    words.append(WORD_INDEX[word])
                choices = tuple(dict.fromkeys(words))
                if position is None:
                    floating.append(choices)
                else:
                    if position in fixed:
                        raise ValueError(f"Line {line_number}: position {position} has two fixed rows")
                    fixed[position] = choices
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Cannot read tokenlist {path}: {error}") from error
    if len(fixed) + len(floating) != 12:
        raise ValueError(
            f"Tokenlist has {len(fixed)} fixed and {len(floating)} permuting rows "
            f"({len(fixed) + len(floating)} total); exactly 12 populated rows are required")
    return {p - 1: choices for p, choices in fixed.items()}, tuple(floating)


def tokenlist_candidate_indices(fixed, floating):
    unfilled = tuple(p for p in range(12) if p not in fixed)
    position_choices = [fixed.get(p) for p in range(12)]
    for assignment in unique_permutations(floating):
        for position, choices in zip(unfilled, assignment):
            position_choices[position] = choices
        yield from itertools.product(*position_choices)


def search_tokenlist_file(path, target_address, processes=None,
                          batch_size=DEFAULT_BATCH_SIZE):
    if not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address (expected an r-address, not X...).")
        return []
    try:
        fixed, floating = load_tokenlist(path)
    except ValueError as error:
        print(f"\nTokenlist error: {error}")
        return []
    counts = Counter(floating)
    distinct = math.factorial(len(floating))
    for frequency in counts.values():
        distinct //= math.factorial(frequency)
    total = (distinct * math.prod(map(len, fixed.values()))
             * math.prod(map(len, floating)))
    print(f"\nTokenlist: {Path(path).expanduser()}")
    print(f"Fixed rows: {len(fixed)} | Permuting rows: {len(floating)} | "
          f"Unique row assignments: {distinct:,}")
    if total > 100_000_000:
        print("Warning: this tokenlist describes a very large search space.")
    return run_search("Tokenlist XRP Address Search", total,
                      tokenlist_candidate_indices(fixed, floating),
                      dict(mode=9, target=target_address),
                      processes, batch_size, stop_on_first=True)


def load_tokenlist_word_pool(path):
    path = Path(path).expanduser()
    words = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                for word in line.split("#", 1)[0].casefold().split():
                    if word not in WORD_INDEX:
                        raise ValueError(f"Line {line_number}: unknown BIP-39 word {word!r}")
                    words.append(word)
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Cannot read tokenlist {path}: {error}") from error
    choices = tuple(dict.fromkeys(words))
    if not choices:
        raise ValueError("The tokenlist contains no BIP-39 candidate words")
    return choices


def find_missing_words_from_tokenlist(path, known_words, num_missing,
                                      processes=None, batch_size=DEFAULT_BATCH_SIZE,
                                      on_match=None, collect_results=True,
                                      preview_limit=None):
    try:
        word_pool = load_tokenlist_word_pool(path)
    except ValueError as error:
        print(f"\nTokenlist error: {error}")
        return [] if collect_results else 0
    print(f"\nTokenlist: {Path(path).expanduser()} | "
          f"Distinct BIP-39 candidate words: {len(word_pool):,}")
    return find_missing_words(known_words, num_missing, word_pool, processes,
                              batch_size, on_match=on_match,
                              collect_results=collect_results,
                              preview_limit=preview_limit)


def find_valid_tokenlist_seeds(path, processes=None, batch_size=DEFAULT_BATCH_SIZE,
                               on_match=None, collect_results=True, preview_limit=None):
    try:
        fixed, floating = load_tokenlist(path)
    except ValueError as error:
        print(f"\nTokenlist error: {error}")
        return [] if collect_results else 0
    counts = Counter(floating)
    distinct = math.factorial(len(floating))
    for frequency in counts.values():
        distinct //= math.factorial(frequency)
    total = (distinct * math.prod(map(len, fixed.values()))
             * math.prod(map(len, floating)))
    print(f"\nTokenlist: {Path(path).expanduser()}")
    print(f"Fixed rows: {len(fixed)} | Permuting rows: {len(floating)} | "
          f"Unique row assignments: {distinct:,}")
    print("Only valid 12-word BIP-39 phrases with no repeated words are output.")
    if total > 100_000_000:
        print("Warning: this tokenlist describes a very large search space.")
    return run_search("Valid Tokenlist Seeds", total,
                      tokenlist_candidate_indices(fixed, floating),
                      dict(mode=12), processes, batch_size, on_match=on_match,
                      collect_results=collect_results, preview_limit=preview_limit)


def search_address_pattern(partial_words, target_pattern, wordlist,
                           processes=None, batch_size=DEFAULT_BATCH_SIZE):
    if len(partial_words) > 12:
        print("\nEnter no more than 12 known words.")
        return []
    indices = prepare_words(partial_words)
    candidate_indices = prepare_words(wordlist)
    if indices is None or candidate_indices is None:
        return []
    missing = 12 - len(partial_words)
    print(f"\nKeeping the first {len(partial_words)} words fixed; searching the last "
          f"{missing} positions.")
    print("Address ending is case-sensitive; enter a suffix or the full classic address.")
    config = dict(mode=2, words=partial_words, pattern=target_pattern,
                  prefix=pack_indices(indices) << (11 * missing))
    return run_search("Address Pattern Search", len(candidate_indices) ** missing,
                      itertools.product(candidate_indices, repeat=missing),
                      config, processes, batch_size)


def find_missing_words(known_words, num_missing, wordlist, processes=None,
                       batch_size=DEFAULT_BATCH_SIZE, on_match=None,
                       collect_results=True, preview_limit=None,
                       target_address=None):
    count = len(known_words)
    if num_missing < 0 or count + num_missing != 12:
        print(f"\nWord count mismatch: read {count} known words + {num_missing} missing "
              f"= {count + num_missing}; expected 12.")
        return [] if collect_results else 0
    address_search = target_address is not None
    if address_search and not is_classic_xrp_address(target_address):
        print("\nInvalid XRP classic address (expected an r-address, not X...).")
        return [] if collect_results else 0
    indices = prepare_words(known_words)
    candidate_indices = prepare_words(wordlist)
    if indices is None or candidate_indices is None:
        return [] if collect_results else 0
    if len(set(indices)) != len(indices):
        print("\nRepeated known words detected. Modes 3 and 13 require 12 distinct words.")
        return [] if collect_results else 0
    known = set(indices)
    available = tuple(dict.fromkeys(i for i in candidate_indices if i not in known))
    if len(available) < num_missing:
        print("\nNot enough distinct candidate words to fill the missing positions.")
        return [] if collect_results else 0
    config = dict(mode=13 if address_search else 3, words=known_words,
                  prefix=pack_indices(indices) << (11 * num_missing))
    if address_search:
        config["target"] = target_address
        preview_limit = 0  # never print the recovered phrase for mode 13
    total = math.perm(len(available), num_missing)
    return run_search("Missing Words Address Search" if address_search
                      else "Missing Words Search", total,
                      itertools.permutations(available, num_missing), config,
                      processes, batch_size, on_match, collect_results,
                      preview_limit, stop_on_first=address_search)


def descramble_seed(scrambled_words, wordlist, processes=None,
                    batch_size=DEFAULT_BATCH_SIZE):
    if len(scrambled_words) != 12:
        print("\nSeed phrase must contain exactly 12 words.")
        return []
    indices = prepare_words(scrambled_words)
    if indices is None:
        return []
    if len(set(indices)) != 12:
        print("\nRepeated input words detected. Mode 6 only outputs phrases with "
              "12 distinct words.")
        return []
    return run_search("Descrambling", math.factorial(12),
                      itertools.permutations(indices), dict(mode=6),
                      processes, batch_size)


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
class ChunkedSeedWriter:
    """Stream phrases to sequential files; unique run folder avoids collisions."""

    def __init__(self, output_dir, max_lines=MODE3_LINES_PER_FILE,
                 filename_prefix="missing_words", mode_label="Mode 3"):
        if max_lines < 1:
            raise ValueError("max_lines must be positive")
        self.output_dir = Path(output_dir)
        self.max_lines = max_lines
        self.filename_prefix = filename_prefix
        self.mode_label = mode_label
        self.file_count = 0
        self.lines_in_file = 0
        self.total_lines = 0
        self._output = None

    def write(self, phrase):
        if self._output is None or self.lines_in_file == self.max_lines:
            self.close()
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.file_count += 1
            # "x" mode: never overwrite a previous file.
            path = self.output_dir / f"{self.filename_prefix}_{self.file_count:04d}.txt"
            self._output = path.open("x", encoding="utf-8", buffering=1024 * 1024)
            self.lines_in_file = 0
            print(f"\n{self.mode_label} writing file {self.file_count:,}: {path}")
        self._output.write(phrase + "\n")
        self.lines_in_file += 1
        self.total_lines += 1

    def close(self):
        if self._output is not None:
            self._output.close()
            self._output = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def print_banner():
    print("""
              ╔═══════════════════════════════════════════╗
              ║             🌱 XRP-RECOVER 🌱             ║
              ║         ADVANCED SEED RECOVERY TOOL       ║
              ╚═══════════════════════════════════════════╝
    """)
    print(f"XRP derivation: {XRP_DERIVATION_PATH} (empty BIP-39 passphrase)")
    print("Only classic r-addresses are accepted (X-addresses are rejected).")


def print_menu():
    print("""
    🔍 Available Operations:

    [1] 🔄 Scan Positions Of Seed For 1 Wrong Word......(positions fixed)
    [2] 🎯 Find Trailing Words From Address Pattern.....(positions fixed)
    [3] 🧩 Print Valid Seeds Missing Trailing Words.....(positions fixed)
    [4] ✓ Checks To Validate Single Seed Phrase.........(positions fixed)
    [5] 📋 Display XRP Addresses At Paths /0 To /9......(positions fixed)
    [6] 🔀 Print Valid Unscrambles Of 12 Word Seed......(all pos permute)
    [7] ✨ Generates New Valid 12 Word Seed Phrase & Classic 'r' Address
    [8] 🧩  Recover 1-4 Missing With '?' Placeholders...(positions fixed)
    [9] 📄 Match Target Address From Tokenlist..........(fixed + permute)
    [10] 🔄 Scan Positions Of Seed For 2 Wrong Words....(positions fixed)
    [11] 🔄 Scan Positions Of Seed For 3 Wrong Words....(positions fixed)
    [12] 📄 Print Valid Seeds Using tokenlist.txt.......(fixed + permute)
    [13] 🎯 Match Address From Missing Trailing Words...(positions fixed)
    [14] 🔀 Unscramble Positions With One Wrong Word....(all pos permute)
    [15] 🔀 Unscramble Positions With Two Wrong Words...(all pos permute)
    """)


def validate_seed(words):
    if len(words) not in SUPPORTED_LENGTHS:
        print(f"\n✗ Invalid: Length must be one of {sorted(SUPPORTED_LENGTHS)} words")
        return False
    is_valid = MNEMO.check(" ".join(words))
    if is_valid:
        print("\n✓ Valid seed phrase")
        try:
            address = derive_xrp_address(" ".join(words))
            print(f"XRP Address: {address}")
        except Exception as e:
            print(f"Note: Valid seed but couldn't generate XRP address: {str(e)}")
    else:
        print("\n✗ Invalid seed phrase")
    return is_valid


def display_addresses(seed_phrase):
    try:
        if len(seed_phrase.split()) != 12 or not MNEMO.check(seed_phrase):
            raise ValueError("Invalid 12-word BIP-39 seed phrase")
        seed = MNEMO.to_seed(seed_phrase, passphrase="")
        chain = (Bip44.FromSeed(seed, Bip44Coins.RIPPLE)
                 .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT))
        addresses = []
        print("\nFirst 10 XRP classic addresses for this seed:")
        for index in range(10):
            address = chain.AddressIndex(index).PublicKey().ToAddress()
            path = f"m/44'/144'/0'/0/{index}"
            print(f"{path}: {address}")
            addresses.append((path, address))
        return addresses
    except Exception as e:
        print(f"\nError generating addresses: {str(e)}")
        return None


def generate_new_seed():
    new_seed = MNEMO.generate(strength=128)
    address = derive_xrp_address(new_seed)
    print("\n✨ Generated New Seed Phrase:")
    print(f"{new_seed}")
    print("\n📍 Corresponding XRP Address:")
    print(f"{address}")
    with open("new_seed.txt", "w") as f:
        f.write(f"Seed Phrase:\n{new_seed}\n\nXRP Address:\n{address}")
    print("\n💾 Saved to 'new_seed.txt'")
    return new_seed


# --------------------------------------------------------------------------
# Handlers (take explicit args; no fake input())
# --------------------------------------------------------------------------
def handle_mode_1(mnemonic, address, wordlist, processes, batch_size):
    seed_words = parse_mnemonic_input(mnemonic)
    if len(seed_words) not in SUPPORTED_LENGTHS:
        print(f"\n⚠️ Input contains {len(seed_words)} words; exactly 12 required.")
        return
    matches = scan_positions_for_address(seed_words, address, wordlist,
                                         processes, batch_size)
    if matches:
        print(f"\nFound {len(matches)} matching combinations!")
        with open("position_matches.txt", "w") as f:
            for i, match in enumerate(matches, 1):
                output = (f"\nMatch {i}:\nPosition {match['position']}: "
                          f"{match['original']} -> {match['replacement']}\n"
                          f"Seed phrase:\n{match['phrase']}")
                print(output)
                f.write(output + "\n")
        print("\nResults saved to 'position_matches.txt'")
    else:
        print("\nNo matching combinations found")


def handle_mode_14(mnemonic, address, wordlist, processes, batch_size):
    words = parse_mnemonic_input(mnemonic)
    matches = scan_permuted_one_wrong_word(words, address, wordlist,
                                           processes, batch_size)
    if matches:
        with open("mode14_matches.txt", "w", encoding="utf-8") as output:
            for match in matches:
                output.write(match["phrase"] + "\n")
        print("\nMatch saved to mode14_matches.txt")
    else:
        print("\nNo match found (or search interrupted).")


def handle_mode_2(mnemonic, pattern, wordlist, processes, batch_size):
    partial_words = parse_mnemonic_input(mnemonic)
    matches = search_address_pattern(partial_words, pattern, wordlist,
                                     processes, batch_size)
    if matches:
        print(f"\nFound {len(matches)} matching combinations!")
        with open("pattern_matches.txt", "w") as f:
            for i, match in enumerate(matches, 1):
                output = f"\nMatch {i}:\nAddress: {match['address']}\nSeed: {match['phrase']}"
                print(output)
                f.write(output + "\n")
        print("\nResults saved to 'pattern_matches.txt'")
    else:
        print("\nNo matches found")


def handle_mode_3(mnemonic, num_missing, wordlist, processes, batch_size):
    known_words = parse_mnemonic_input(mnemonic)
    try:
        num_missing = int(num_missing)
    except (TypeError, ValueError):
        print("Please enter a whole number of missing words.")
        return
    print(f"\nInput count: {len(known_words)} known + {num_missing} missing "
          f"= {len(known_words) + num_missing} words")
    if num_missing < 0 or len(known_words) + num_missing != 12:
        print(f"Expected {12 - num_missing} known words for {num_missing} missing words.")
        return
    output_dir = Path("mode3_results") / datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    with ChunkedSeedWriter(output_dir) as output:
        count = find_missing_words(known_words, num_missing, wordlist, processes,
                                   batch_size, on_match=output.write,
                                   collect_results=False, preview_limit=20)
    if count:
        print(f"\nFound {count:,} valid combinations, saved in "
              f"{output.file_count:,} file(s) under '{output_dir}'. "
              f"Maximum {MODE3_LINES_PER_FILE:,} phrases per file.")
    else:
        print("\nNo valid combinations found (or no candidates passed validation).")


def handle_mode_4(mnemonic, *_):
    words = parse_mnemonic_input(mnemonic)
    if len(words) in SUPPORTED_LENGTHS:
        validate_seed(words)
    else:
        print(f"Length must be one of {sorted(SUPPORTED_LENGTHS)} words")


def handle_mode_5(mnemonic, *_):
    words = parse_mnemonic_input(mnemonic)
    if len(words) in SUPPORTED_LENGTHS:
        display_addresses(" ".join(words))
    else:
        print(f"Length must be one of {sorted(SUPPORTED_LENGTHS)} words")


def handle_mode_6(mnemonic, wordlist, processes, batch_size):
    scrambled = parse_mnemonic_input(mnemonic)
    if len(scrambled) not in SUPPORTED_LENGTHS:
        print(f"\n⚠️ Input contains {len(scrambled)} words; exactly 12 required.")
        return
    valid_phrases = descramble_seed(scrambled, wordlist, processes, batch_size)
    if valid_phrases:
        print(f"\nFound {len(valid_phrases)} valid combinations!")
        with open("descrambled.txt", "w") as f:
            for phrase in valid_phrases:
                print(phrase)
                f.write(phrase + "\n")
        print("\nResults saved to 'descrambled.txt'")
    else:
        print("\nNo valid combinations found")


def handle_mode_7(*_):
    generate_new_seed()


def handle_mode_8(mnemonic, address, wordlist, processes, batch_size):
    seed_words = parse_mnemonic_input(mnemonic)
    if len(seed_words) != 12:
        print(f"\n⚠️ Input contains {len(seed_words)} positions; exactly 12 required.")
        return
    count_missing = seed_words.count("?")
    if not 1 <= count_missing <= 4:
        print(f"\n⚠️ Found {count_missing} '?' markers; use between 1 and 4.")
        return
    matches = recover_missing_positions(seed_words, address, wordlist,
                                        processes, batch_size)
    if matches:
        print(f"\nFound {len(matches)} matching combination(s)!")
        with open("missing_positions_matches.txt", "w", encoding="utf-8") as output:
            for i, match in enumerate(matches, 1):
                filled = ", ".join(f"{pos}: {word}" for pos, word in
                                   zip(match["positions"], match["replacements"]))
                text = (f"Match {i}:\nMissing positions filled: {filled}\n"
                        f"XRP address: {match['address']}\n"
                        f"Seed phrase: {match['phrase']}\n")
                print(text)
                output.write(text + "\n")
        print("Results saved to 'missing_positions_matches.txt'")
    else:
        print("\nNo matching combinations found (or search interrupted).")


def handle_mode_9(path, address, processes, batch_size):
    matches = search_tokenlist_file(path, address, processes, batch_size)
    if matches:
        with open("tokenlist_matches.txt", "w", encoding="utf-8") as output:
            for match in matches:
                output.write(f"XRP address: {match['address']}\n"
                             f"Seed phrase: {match['phrase']}\n")
        print(f"\nFound {len(matches)} matching combination(s). "
              "Saved to 'tokenlist_matches.txt'.")
    else:
        print("\nNo matching combinations found (or tokenlist invalid/search interrupted).")


def handle_mode_10(mnemonic, address, wordlist, processes, batch_size):
    seed_words = parse_mnemonic_input(mnemonic)
    if len(seed_words) != 12:
        print(f"\n⚠️ Input contains {len(seed_words)} words. Exactly 12 are required.")
        return
    matches = scan_two_positions_for_address(seed_words, address, wordlist,
                                             processes, batch_size)
    if matches:
        with open("two_wrong_word_matches.txt", "w", encoding="utf-8") as output:
            for number, match in enumerate(matches, 1):
                changes = ", ".join(
                    f"{pos}: {old} -> {new}" for pos, old, new in zip(
                        match["positions"], match["originals"], match["replacements"]))
                text = (f"Match {number}:\nChanged positions: {changes}\n"
                        f"XRP address: {match['address']}\n"
                        f"Seed phrase: {match['phrase']}\n")
                print(text)
                output.write(text + "\n")
        print(f"\nFound {len(matches)} matching combination(s). "
              "Saved to 'two_wrong_word_matches.txt'.")
    else:
        print("\nNo matching combinations found (or search interrupted).")


def handle_mode_15(mnemonic, address, wordlist, processes, batch_size):
    words = parse_mnemonic_input(mnemonic)
    matches = scan_permuted_two_wrong_words(words, address, wordlist,
                                             processes, batch_size)
    if matches:
        with open("mode15_matches.txt", "w", encoding="utf-8") as output:
            for match in matches:
                output.write(f"XRP address: {match['address']}\n"
                             f"Seed phrase: {match['phrase']}\n")
        print("\nMatches saved to mode15_matches.txt")
    else:
        print("\nNo matches found (or search interrupted).")


def handle_mode_11(mnemonic, address, wordlist, processes, batch_size):
    seed_words = parse_mnemonic_input(mnemonic)
    if len(seed_words) != 12:
        print(f"\n⚠️ Input contains {len(seed_words)} words. Exactly 12 are required.")
        return
    matches = scan_three_positions_for_address(seed_words, address, wordlist,
                                               processes, batch_size)
    if matches:
        with open("three_wrong_word_matches.txt", "w", encoding="utf-8") as output:
            for number, match in enumerate(matches, 1):
                changes = ", ".join(
                    f"{pos}: {old} -> {new}" for pos, old, new in zip(
                        match["positions"], match["originals"], match["replacements"]))
                text = (f"Match {number}:\nChanged positions: {changes}\n"
                        f"XRP address: {match['address']}\n"
                        f"Seed phrase: {match['phrase']}\n")
                print(text)
                output.write(text + "\n")
        print(f"\nFound {len(matches)} matching combination(s). "
              "Saved to 'three_wrong_word_matches.txt'.")
    else:
        print("\nNo matching combinations found (or search interrupted).")


def handle_mode_12(path, processes, batch_size):
    output_dir = Path("mode12_results") / datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    with ChunkedSeedWriter(output_dir, filename_prefix="tokenlist_valid_seeds",
                           mode_label="Mode 12") as output:
        count = find_valid_tokenlist_seeds(path, processes, batch_size,
                                           on_match=output.write,
                                           collect_results=False, preview_limit=20)
    if count:
        print(f"\nFound {count:,} valid combinations, saved in "
              f"{output.file_count:,} file(s) under '{output_dir}'. "
              f"Maximum {MODE3_LINES_PER_FILE:,} phrases per file.")
    else:
        print("\nNo valid combinations found (or tokenlist invalid/search interrupted).")


def handle_mode_13(mnemonic, num_missing, address, wordlist, processes, batch_size,
                   allow_print=False):
    known_words = parse_mnemonic_input(mnemonic)
    try:
        num_missing = int(num_missing)
    except (TypeError, ValueError):
        print("Please enter a whole number of missing words.")
        return
    if num_missing < 0 or len(known_words) + num_missing != 12:
        print(f"Expected {12 - num_missing} known words for {num_missing} missing words.")
        return
    matches = find_missing_words(known_words, num_missing, wordlist, processes,
                                 batch_size, target_address=address)
    if matches:
        output_dir = Path("mode13_results") / datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        try:
            output_dir.mkdir(parents=True, exist_ok=False)
            output_path = output_dir / "target_match.txt"
            descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(f"XRP address: {matches[0]['address']}\n"
                             f"Seed phrase: {matches[0]['phrase']}\n")
        except OSError as error:
            print(f"\nTarget matched, but could not save the private result: {error}")
            return
        print(f"\nTarget matched. Private result saved to '{output_path}'.")
        if allow_print:
            print(f"Seed phrase: {matches[0]['phrase']}")
    else:
        print("\nNo target address match found (or search interrupted/invalid input).")


# --------------------------------------------------------------------------
# CLI / menu
# --------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(description="12-word XRP seed recovery")
    parser.add_argument("--processes", type=int, default=DEFAULT_PROCESSES,
                        help="CPU workers for search modes (default: CPU count)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help="Candidates per worker task (default: 1024)")
    parser.add_argument("--pbkdf2-backend", choices=("auto", "reference"), default="auto")
    parser.add_argument("--mode", type=int, choices=range(1, 16), metavar="1-15")
    parser.add_argument("--address", help="Target classic XRP address (r...)")
    parser.add_argument("--pattern", help="Address suffix for mode 2")
    parser.add_argument("--mnemonic", help="Space-separated words; '?' for missing")
    parser.add_argument("--num-missing", type=int, help="Missing trailing words (modes 3/13)")
    parser.add_argument("--tokenlist", default="tokenlist.txt")
    parser.add_argument("--worker", metavar="N/TOTAL",
                        help="Optional distributed shard, e.g. 1/3")
    parser.add_argument("--output", help="Output directory override for chunked modes")
    parser.add_argument("--allow-print", action="store_true",
                        help="Mode 13: also print the recovered phrase to the terminal")
    return parser


def dispatch(mode, args, wordlist):
    """Call the right handler with explicit arguments (no input() faking)."""
    p = args.processes
    b = args.batch_size
    if mode == "1":
        handle_mode_1(args.mnemonic, args.address, wordlist, p, b)
    elif mode == "2":
        handle_mode_2(args.mnemonic, args.pattern or args.address, wordlist, p, b)
    elif mode == "3":
        handle_mode_3(args.mnemonic, args.num_missing, wordlist, p, b)
    elif mode == "4":
        handle_mode_4(args.mnemonic)
    elif mode == "5":
        handle_mode_5(args.mnemonic)
    elif mode == "6":
        handle_mode_6(args.mnemonic, wordlist, p, b)
    elif mode == "7":
        handle_mode_7()
    elif mode == "8":
        handle_mode_8(args.mnemonic, args.address, wordlist, p, b)
    elif mode == "9":
        handle_mode_9(args.tokenlist, args.address, p, b)
    elif mode == "10":
        handle_mode_10(args.mnemonic, args.address, wordlist, p, b)
    elif mode == "14":
        handle_mode_14(args.mnemonic, args.address, wordlist, p, b)
    elif mode == "15":
        handle_mode_15(args.mnemonic, args.address, wordlist, p, b)
    elif mode == "11":
        handle_mode_11(args.mnemonic, args.address, wordlist, p, b)
    elif mode == "12":
        handle_mode_12(args.tokenlist, p, b)
    elif mode == "13":
        handle_mode_13(args.mnemonic, args.num_missing, args.address, wordlist, p, b,
                       allow_print=args.allow_print)
    else:
        print("Invalid mode number")
        return False
    return True


def interactive(args):
    clear_screen()
    print_banner()
    print_menu()
    mode = input("\n📎 Enter mode number (1-15): ").strip()
    args.mode = int(mode) if mode.isdigit() else 0
    if mode == "1":
        args.mnemonic = input("\n🔤 Enter your 12-word seed phrase:\n").strip()
        args.address = input("🎯 Enter target classic XRP address:\n").strip()
    elif mode == "2":
        args.mnemonic = input("\nEnter known leading words (space-separated):\n").strip()
        args.pattern = input("Enter address suffix/pattern to find:\n").strip()
    elif mode == "3":
        args.mnemonic = input("\nEnter known leading words (space-separated):\n").strip()
        args.num_missing = input("Enter number of missing trailing words:\n").strip()
    elif mode == "4":
        args.mnemonic = input("\nEnter seed phrase to validate:\n").strip()
    elif mode == "5":
        args.mnemonic = input("\nEnter seed phrase:\n").strip()
    elif mode == "6":
        args.mnemonic = input("\n🔤 Enter your 12 scrambled words:\n").strip()
    elif mode == "7":
        pass
    elif mode == "8":
        print("\nEnter all 12 positions; use '?' for each missing word (1-4).")
        args.mnemonic = input().strip()
        args.address = input("🎯 Enter target classic XRP address:\n").strip()
    elif mode == "9":
        args.tokenlist = (input("\n📄 Enter tokenlist path [tokenlist.txt]:\n")
                          .strip().strip('"') or "tokenlist.txt")
        args.address = input("🎯 Enter target classic XRP address:\n").strip()
    elif mode == "10":
        args.mnemonic = input("\n🔤 Enter your 12-word seed phrase (2 may be wrong):\n").strip()
        args.address = input("🎯 Enter target classic XRP address:\n").strip()
    elif mode == "14":
        args.mnemonic = input("\nEnter 12 scrambled words (1 wrong):\n").strip()
        args.address = input("Enter target XRP classic address:\n").strip()
    elif mode == "15":
        args.mnemonic = input("\nEnter 12 scrambled words (2 wrong):\n").strip()
        args.address = input("Enter target XRP classic address:\n").strip()
    elif mode == "11":
        args.mnemonic = input("\n🔤 Enter your 12-word seed phrase (3 may be wrong):\n").strip()
        args.address = input("🎯 Enter target classic XRP address:\n").strip()
    elif mode == "12":
        args.tokenlist = (input("\n📄 Enter tokenlist path [tokenlist.txt]:\n")
                          .strip().strip('"') or "tokenlist.txt")
    elif mode == "13":
        args.mnemonic = input("\nEnter known leading words (space-separated):\n").strip()
        args.num_missing = input("Enter number of missing trailing words:\n").strip()
        args.address = input("🎯 Enter target classic XRP address:\n").strip()
    return str(args.mode) if args.mode else ""


def main(argv=None):
    global PBKDF2_BACKEND, DISTRIBUTED_WORKER
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.worker:
        match = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", args.worker)
        if not match or int(match[1]) > int(match[2]):
            parser.error("--worker must be N/TOTAL, with 1 <= N <= TOTAL")
        DISTRIBUTED_WORKER = (int(match[1]), int(match[2]))
    PBKDF2_BACKEND = args.pbkdf2_backend
    if args.processes < 1 or args.batch_size < 1:
        parser.error("--processes and --batch-size must be positive")

    # Validate CLI-only combinations early.
    if args.mode is not None:
        needs_mnemonic = args.mode in (1, 2, 3, 4, 5, 6, 8, 10, 11, 13, 14, 15)
        needs_address = args.mode in (1, 2, 8, 9, 10, 11, 13, 14, 15)
        if needs_mnemonic and not args.mnemonic:
            parser.error(f"--mode {args.mode} requires --mnemonic")
        if needs_address and not (args.address or args.pattern):
            parser.error(f"--mode {args.mode} requires --address")

    if args.mode is None:
        mode = interactive(args)
    else:
        mode = str(args.mode)
    if not mode:
        return 1
    ok = dispatch(mode, args, WORDLIST)
    return 0 if ok else 1


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
