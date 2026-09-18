
from mnemonic import Mnemonic
import itertools
import argparse
import multiprocessing as mp
import hashlib
import hmac
from datetime import datetime
import time
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins
import os
import re
try:
    # bip_utils normally installs coincurve; using it directly avoids the
    # framework overhead of rebuilding a Bip44 object tree for each phrase.
    from coincurve import PrivateKey as _CoincurvePrivateKey
except ImportError:
    _CoincurvePrivateKey = None
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import math
"""
Advanced 12-Word Seed Recovery Tool
This script provides various functionalities to work with XRP seed phrases, including:
1. Scanning positions for address match
2. Searching by address pattern
3. Finding missing words
4. Validating seed phrases
5. Displaying addresses
6. Descrambling seed phrases
Classes:
    ProgressTracker: Tracks and displays the progress of long-running operations.
Functions:
    validate_xrp_address(seed_phrase: str, target_address: str) -> bool:
        Validates if the XRP address generated from the given seed phrase matches the target address.
    validate_seed(words: list) -> bool:
        Validates if the provided list of words forms a valid seed phrase and optionally displays the corresponding XRP address.
    display_addresses(seed_phrase: str) -> str:
        Displays the XRP address generated from the given seed phrase.
    scan_positions_for_address(seed_words: list, target_address: str, wordlist: set) -> list:
        Scans all positions of the seed words to find a match with the target XRP address.
    search_address_pattern(partial_words: list, target_pattern: str, wordlist: set) -> list:
        Searches for seed phrases that generate XRP addresses ending with the target pattern.
    find_missing_words(known_words: list, num_missing: int, wordlist: set) -> list:
        Finds valid seed phrases by filling in the missing words from the known words dictionary.
    descramble_seed(scrambled_words: list, wordlist: set) -> list:
        Finds valid seed phrases by testing permutations of the scrambled words.
    main():
        Entry point of the script. Provides a menu for the user to select the desired functionality.
"""

def clear_screen():
    # Cross-platform screen clearing
    os.system('cls' if os.name == 'nt' else 'clear')

class ProgressTracker:
    def __init__(self, mode_name, total=None):
        self.start_time = time.time()
        self.last_update = 0.0
        self.processed = 0
        self.mode_name = mode_name
        self.total = total

    @staticmethod
    def _format_duration(seconds):
        if seconds is None or not math.isfinite(seconds) or seconds < 0:
            return "--:--:--"
        seconds = int(seconds)
        hours, rem = divmod(seconds, 3600)
        minutes, secs = divmod(rem, 60)
        if hours >= 24:
            days, hours = divmod(hours, 24)
            return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def _render(self, final=False):
        now = time.time()
        elapsed = max(now - self.start_time, 0.000001)
        speed = self.processed / elapsed

        if self.total:
            fraction = min(1.0, self.processed / self.total)
            bar_length = 30
            filled = min(bar_length, int(bar_length * fraction))
            bar = "█" * filled + "░" * (bar_length - filled)
            remaining = max(0, self.total - self.processed)
            eta = remaining / speed if speed > 0 else None
            line = (
                f"[{bar}] {fraction * 100:6.2f}% | "
                f"{self.processed:,}/{self.total:,} | "
                f"{speed:,.0f}/s | "
                f"Elapsed {self._format_duration(elapsed)} | "
                f"ETA {self._format_duration(eta)}"
            )
        else:
            line = (
                f"Tested {self.processed:,} | {speed:,.0f}/s | "
                f"Elapsed {self._format_duration(elapsed)}"
            )

        prefix = "✓ " if final else "⚡ "
        print(f"\r\033[K{prefix}{self.mode_name} | {line}",
              end="\n" if final else "", flush=True)

    def update(self, count=1):
        self.processed += count
        now = time.time()
        if now - self.last_update >= 1.0:
            self._render()
            self.last_update = now

    def finish(self):
        self._render(final=True)

XRP_DERIVATION_PATH = "m/44'/144'/0'/0/0"


def derive_xrp_address(seed_phrase: str) -> str:
    """Derive the first XRP classic address using m/44'/144'/0'/0/0."""
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    account = (
        Bip44.FromSeed(seed_bytes, Bip44Coins.RIPPLE)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    return account.PublicKey().ToAddress()


def validate_xrp_address(seed_phrase: str, target_address: str) -> bool:
    # XRP classic addresses use a case-sensitive Base58 alphabet.
    return derive_xrp_address(seed_phrase) == target_address

SEED_LENGTH = 12

# Keep workers at module scope so they can be pickled by Windows' "spawn"
# multiprocessing implementation.
_WORKER_MNEMO = None
_WORKER_WORD_TO_INDEX = None
_MODE8_FIXED = None
_MODE8_UNANCHORED_POSITIONS = None
_MODE8_GROUPS = None
_MODE8_CHOICES_PER_ORDER = None
_MODE8_TARGET_ACCOUNT_ID = None

# Constants used by Mode 8's fixed m/44'/144'/0'/0/0 derivation path.
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_HARDENED = 0x80000000
_MODE8_PATH = (44 | _HARDENED, 144 | _HARDENED, 0 | _HARDENED, 0, 0)
_XRP_BASE58_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_XRP_BASE58_VALUES = {character: index for index, character in enumerate(_XRP_BASE58_ALPHABET)}


def _init_worker():
    global _WORKER_MNEMO, _WORKER_WORD_TO_INDEX
    _WORKER_MNEMO = Mnemonic("english")
    _WORKER_WORD_TO_INDEX = {
        word: index for index, word in enumerate(_WORKER_MNEMO.wordlist)
    }


def _init_mode8_worker(fixed, unanchored_positions, groups,
                       choices_per_order, target_account_id):
    """Initialize immutable Mode 8 data once per process, not once per task."""
    global _MODE8_FIXED, _MODE8_UNANCHORED_POSITIONS, _MODE8_GROUPS
    global _MODE8_CHOICES_PER_ORDER, _MODE8_TARGET_ACCOUNT_ID
    _init_worker()
    _MODE8_FIXED = fixed
    _MODE8_UNANCHORED_POSITIONS = unanchored_positions
    _MODE8_GROUPS = groups
    _MODE8_CHOICES_PER_ORDER = choices_per_order
    _MODE8_TARGET_ACCOUNT_ID = target_account_id


def _compressed_public_key(private_key):
    if _CoincurvePrivateKey is not None:
        return _CoincurvePrivateKey.from_int(private_key).public_key.format(
            compressed=True
        )
    key = ec.derive_private_key(private_key, ec.SECP256K1())
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def _bip32_private_child(private_key, chain_code, index):
    if index & _HARDENED:
        data = b"\x00" + private_key.to_bytes(32, "big")
    else:
        data = _compressed_public_key(private_key)
    digest = hmac.new(chain_code, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    child = (int.from_bytes(digest[:32], "big") + private_key) % _SECP256K1_ORDER
    if child == 0 or int.from_bytes(digest[:32], "big") >= _SECP256K1_ORDER:
        raise ValueError("invalid BIP-32 child key")
    return child, digest[32:]


def _mode8_account_id(phrase):
    """Return the 20-byte XRP account ID for the fixed Mode 8 BIP44 path."""
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("ascii"), b"mnemonic", 2048)
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_key = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]
    if private_key == 0 or private_key >= _SECP256K1_ORDER:
        raise ValueError("invalid BIP-32 master key")
    for index in _MODE8_PATH:
        private_key, chain_code = _bip32_private_child(private_key, chain_code, index)
    public_key = _compressed_public_key(private_key)
    return hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest()


def _decode_xrp_account_id(address):
    """Validate a classic XRP address and return its 20-byte account ID."""
    number = 0
    try:
        for character in address:
            number = number * 58 + _XRP_BASE58_VALUES[character]
    except KeyError as exc:
        raise ValueError("address contains a non-XRP Base58 character") from exc
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(address) - len(address.lstrip(_XRP_BASE58_ALPHABET[0]))
    decoded = b"\x00" * leading_zeroes + decoded
    if len(decoded) != 25 or decoded[0] != 0:
        raise ValueError("not a valid XRP classic address")
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if not hmac.compare_digest(checksum, expected):
        raise ValueError("XRP classic address checksum is invalid")
    return payload[1:]


def _fill_placeholders(template_words, combo):
    """Replace ? tokens from left to right with words from combo."""
    replacements = iter(combo)
    return tuple(next(replacements) if word == "?" else word
                 for word in template_words)


def _is_valid_12_word_checksum(words):
    """Fast BIP-39 checksum test specialized for a 12-word mnemonic."""
    try:
        packed = 0
        for word in words:
            packed = (packed << 11) | _WORKER_WORD_TO_INDEX[word]
    except KeyError:
        return False
    entropy = (packed >> 4).to_bytes(16, "big")
    expected_checksum = hashlib.sha256(entropy).digest()[0] >> 4
    return (packed & 0x0F) == expected_checksum


def _batched(iterable, size):
    """Yield tuples of up to size items without materializing the search."""
    iterator = iter(iterable)
    while True:
        batch = tuple(itertools.islice(iterator, size))
        if not batch:
            return
        yield batch


def _scan_batch_worker(task):
    template_words, placeholder_positions, combos, target_address, checksum_prevalidated = task
    completed_words = list(template_words)
    for combo in combos:
        for offset, position in enumerate(placeholder_positions):
            completed_words[position] = combo[offset]
        if not checksum_prevalidated and not _is_valid_12_word_checksum(completed_words):
            continue
        phrase = " ".join(completed_words)
        try:
            address = derive_xrp_address(phrase)
        except Exception:
            continue
        if address == target_address:
            return len(combos), {
                'match_type': 'placeholders',
                'replacements': [(position + 1, combo[offset]) for offset, position in enumerate(placeholder_positions)],
                'phrase': phrase,
                'address': address
            }
    return len(combos), None


def _mode1_candidate_plan(template_words, placeholder_positions, wordlist):
    """
    Build Mode 1 candidate iterator and checksum strategy.
    When the final word is a placeholder, only generate candidates that can
    satisfy the 12-word BIP-39 checksum.
    """
    placeholder_count = len(placeholder_positions)
    naive_total = len(wordlist) ** placeholder_count
    if 11 not in placeholder_positions:
        return itertools.product(wordlist, repeat=placeholder_count), False, naive_total

    mnemo = Mnemonic("english")
    word_to_index = {word: index for index, word in enumerate(mnemo.wordlist)}
    valid_words = tuple(word for word in wordlist if word in word_to_index)
    if not valid_words:
        return iter(()), True, 0

    first_eleven = template_words[:11]
    for word in first_eleven:
        if word != "?" and word not in word_to_index:
            return iter(()), True, 0

    non_last_positions = tuple(position for position in placeholder_positions
                               if position != 11)
    valid_last_indexes = {word_to_index[word] for word in valid_words}
    full_bip39_wordlist = (
        len(valid_words) == len(mnemo.wordlist)
        and set(valid_words) == set(mnemo.wordlist)
    )

    def _combos():
        prefix_words = list(first_eleven)
        for non_last_combo in itertools.product(valid_words, repeat=len(non_last_positions)):
            for offset, position in enumerate(non_last_positions):
                if position < 11:
                    prefix_words[position] = non_last_combo[offset]
            try:
                packed = 0
                for word in prefix_words:
                    packed = (packed << 11) | word_to_index[word]
            except KeyError:
                continue

            for entropy_suffix in range(128):
                entropy = ((packed << 7) | entropy_suffix).to_bytes(16, "big")
                checksum = hashlib.sha256(entropy).digest()[0] >> 4
                last_index = (entropy_suffix << 4) | checksum
                if last_index not in valid_last_indexes:
                    continue
                last_word = mnemo.wordlist[last_index]
                non_last_offset = 0
                combo = []
                for position in placeholder_positions:
                    if position == 11:
                        combo.append(last_word)
                    else:
                        combo.append(non_last_combo[non_last_offset])
                        non_last_offset += 1
                yield tuple(combo)

    if full_bip39_wordlist:
        optimized_total = (len(valid_words) ** len(non_last_positions)) * 128
    else:
        optimized_total = naive_total
    return _combos(), True, optimized_total


def _pattern_batch_worker(task):
    template_words, combos, target_pattern = task
    matches = []
    for combo in combos:
        completed_words = _fill_placeholders(template_words, combo)
        if not _is_valid_12_word_checksum(completed_words):
            continue
        phrase = " ".join(completed_words)
        try:
            address = derive_xrp_address(phrase)
        except Exception:
            continue
        if address.endswith(target_pattern):
            matches.append({'phrase': phrase, 'address': address})
    return len(combos), matches


def _missing_batch_worker(task):
    template_words, combos = task
    phrases = []
    for combo in combos:
        completed_words = _fill_placeholders(template_words, combo)
        if _is_valid_12_word_checksum(completed_words):
            phrases.append(" ".join(completed_words))
    return len(combos), phrases


def _validate_seed_worker(words):
    phrase = " ".join(words)
    if not _WORKER_MNEMO.check(phrase):
        return False, None, None
    try:
        return True, derive_xrp_address(phrase), None
    except Exception as exc:
        return True, None, str(exc)


def _pool_results(worker, tasks, processes):
    """Yield unordered results and shut workers down cleanly on Ctrl+C."""
    with mp.Pool(processes=processes, initializer=_init_worker) as pool:
        try:
            # Each task is already a sizeable batch, so Pool chunksize stays 1.
            yield from pool.imap_unordered(worker, tasks, chunksize=1)
        except KeyboardInterrupt:
            pool.terminate()
            raise

def validate_seed(words):
    if len(words) != SEED_LENGTH:
        print(f"\n✗ Invalid: Seed phrase must contain exactly {SEED_LENGTH} words")
        return False
        
    mnemo = Mnemonic("english")
    is_valid = mnemo.check(" ".join(words))
    
    if is_valid:
        print("\n✓ Valid seed phrase")
        try:
            address = derive_xrp_address(" ".join(words))
            print(f"XRP Address ({XRP_DERIVATION_PATH}): {address}")
        except Exception as e:
            print(f"Note: Valid seed but couldn't generate XRP address: {str(e)}")
    else:
        print("\n✗ Invalid seed phrase")
    return is_valid

def display_addresses(seed_phrase):
    try:
        address = derive_xrp_address(seed_phrase)
        print("\nAddresses for this seed:")
        print(f"XRP ({XRP_DERIVATION_PATH}): {address}")
        return address
    except Exception as e:
        print(f"\nError generating addresses: {str(e)}")
        return None

def scan_positions_for_address(seed_words, target_address, wordlist, processes=1,
                               batch_size=1024):
    if len(seed_words) != SEED_LENGTH:
        print(f"\n✗ Invalid: Seed phrase must contain exactly {SEED_LENGTH} words")
        return []

    placeholder_count = seed_words.count("?")
    if not 1 <= placeholder_count <= 5:
        print("\n✗ Module 1 requires between 1 and 5 ? placeholders")
        return []
    template_words = tuple(seed_words)
    placeholder_positions = tuple(index for index, word in enumerate(template_words)
                                  if word == "?")
    combos, checksum_prevalidated, total = _mode1_candidate_plan(
        template_words, placeholder_positions, wordlist
    )
    tracker = ProgressTracker("Position Scanner", total)
    matches = []
    
    print(f"\nScanning all positions against target address: {target_address}")
    print("Press Ctrl+C to stop scanning at any time\n")

    print(f"Replacing {placeholder_count} marked position(s)")
    print(f"Candidate space: {total:,}")
    if placeholder_count >= 4:
        print("⚠️ This search space is extremely large and may be impractical.")
    
    try:
        tasks = ((template_words, placeholder_positions, batch,
                  target_address, checksum_prevalidated)
                 for batch in _batched(combos, batch_size))
        for tested, match in _pool_results(_scan_batch_worker, tasks, processes):
            tracker.update(tested)
            if match:
                matches.append(match)
                print("\n✓ Found target address match!")
                for position, replacement in match['replacements']:
                    print(f"Position {position}: ? -> {replacement}")
                print(f"Seed: {match['phrase']}\n")
                break
        if not matches:
            tracker.finish()
                
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
        
    return matches
def search_address_pattern(partial_words, target_pattern, wordlist, processes=1,
                           batch_size=1024):
    if "?" in partial_words:
        if len(partial_words) != SEED_LENGTH:
            print(f"\n✗ When using ?, enter exactly {SEED_LENGTH} positions")
            return []
        template_words = tuple(partial_words)
        missing_count = partial_words.count("?")
    else:
        if len(partial_words) >= SEED_LENGTH:
            print(f"\n✗ Enter fewer than {SEED_LENGTH} known words for pattern search")
            return []
        missing_count = SEED_LENGTH - len(partial_words)
        # Preserve the original behavior: omitted words are trailing positions.
        template_words = tuple(partial_words) + ("?",) * missing_count
    total = len(wordlist) ** missing_count
    tracker = ProgressTracker("Address Pattern Search", total)
    valid_phrases = []
    print(f"\nSearching for seeds with address ending in: {target_pattern}")
    print(f"Using {SEED_LENGTH - missing_count} known words, searching {missing_count} positions")
    
    try:
        # Missing positions are ordered and may contain the same word, so this
        # must be a Cartesian product rather than combinations.
        combos = itertools.product(wordlist, repeat=missing_count)
        tasks = ((template_words, batch, target_pattern)
                 for batch in _batched(combos, batch_size))
        for tested, batch_matches in _pool_results(
                _pattern_batch_worker, tasks, processes):
            tracker.update(tested)
            for match in batch_matches:
                valid_phrases.append(match)
                print("\nMatch found!")
                print(f"Address: {match['address']}")
                print(f"Seed: {match['phrase']}\n")
        tracker.finish()
            
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
        
    return valid_phrases

def find_missing_words(known_words, num_missing, wordlist, processes=1,
                       batch_size=1024):
    if "?" in known_words:
        if len(known_words) != SEED_LENGTH:
            print(f"\n✗ When using ?, enter exactly {SEED_LENGTH} positions")
            return []
        inferred_missing = known_words.count("?")
        if num_missing is not None and num_missing != inferred_missing:
            print(f"\n✗ Found {inferred_missing} ? placeholders, not {num_missing}")
            return []
        num_missing = inferred_missing
        template_words = tuple(known_words)
    else:
        if num_missing is None:
            print("\n✗ Enter the number of omitted trailing words")
            return []
        template_words = tuple(known_words) + ("?",) * num_missing

    if num_missing < 1 or len(template_words) != SEED_LENGTH:
        print(
            f"\n✗ Known words plus missing words must total exactly "
            f"{SEED_LENGTH} words"
        )
        return []

    total = len(wordlist) ** num_missing
    tracker = ProgressTracker("Missing Words Search", total)
    valid_phrases = []
    print(f"\nSearching for {num_missing} missing words...")
    
    try:
        # Each blank is a distinct position; order and repeated words matter.
        combos = itertools.product(wordlist, repeat=num_missing)
        tasks = ((template_words, batch)
                 for batch in _batched(combos, batch_size))
        for tested, batch_phrases in _pool_results(
                _missing_batch_worker, tasks, processes):
            tracker.update(tested)
            for phrase in batch_phrases:
                valid_phrases.append(phrase)
                print(f"\nFound valid phrase: {phrase}")
        tracker.finish()
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
        
    return valid_phrases

def load_position_tokenlist(filename):
    """
    Anchored tokens stay fixed. Each unanchored line is a candidate group.
    Unanchored groups are permuted ONLY among unanchored positions.
    """
    fixed = {position: [] for position in range(1, SEED_LENGTH + 1)}
    token_re = re.compile(r"\^(\d+)\^([^\s#]+)")
    groups = []

    try:
        with open(filename, "r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                anchored_matches = token_re.findall(line)
                if anchored_matches:
                    remainder = token_re.sub("", line).split("#", 1)[0].strip()
                    if remainder:
                        print(f"✗ Line {line_number} mixes anchored and unanchored tokens")
                        return None
                    for position_text, word in anchored_matches:
                        position = int(position_text)
                        word = word.lower()
                        if not 1 <= position <= SEED_LENGTH:
                            print(f"⚠️ Ignoring out-of-range position ^{position}^")
                            continue
                        if word not in fixed[position]:
                            fixed[position].append(word)
                else:
                    content = line.split("#", 1)[0].strip()
                    if content:
                        words = []
                        for word in content.lower().split():
                            if word not in words:
                                words.append(word)
                        if words:
                            groups.append(tuple(words))
    except OSError as exc:
        print(f"\n✗ Could not read tokenlist: {exc}")
        return None

    unanchored_positions = tuple(
        pos for pos in range(1, SEED_LENGTH + 1) if not fixed[pos]
    )

    if len(groups) != len(unanchored_positions):
        print(
            f"\n✗ Found {len(groups)} unanchored candidate group(s), "
            f"but there are {len(unanchored_positions)} unanchored position(s)."
        )
        print("Use exactly one unanchored line per unanchored position.")
        return None

    return {
        "fixed": {pos: tuple(words) for pos, words in fixed.items() if words},
        "unanchored_positions": unanchored_positions,
        "groups": tuple(groups),
    }


def _nth_permutation(items, index):
    """Return the index-th positional permutation without enumerating earlier ones."""
    remaining = list(items)
    result = []
    for width in range(len(remaining), 0, -1):
        block = math.factorial(width - 1)
        choice, index = divmod(index, block)
        result.append(remaining.pop(choice))
    return tuple(result)


def _product_indices(index, candidate_lists):
    """Decode an itertools.product index into mixed-radix list indices."""
    indices = [0] * len(candidate_lists)
    for position in range(len(candidate_lists) - 1, -1, -1):
        index, indices[position] = divmod(index, len(candidate_lists[position]))
    return indices


def _advance_product_indices(indices, candidate_lists):
    """Advance mixed-radix indices by one; return False after the last item."""
    for position in range(len(indices) - 1, -1, -1):
        indices[position] += 1
        if indices[position] < len(candidate_lists[position]):
            return True
        indices[position] = 0
    return False


def _tokenlist_cartesian_batch_worker(task):
    start, stop = task
    fixed = _MODE8_FIXED
    unanchored_positions = _MODE8_UNANCHORED_POSITIONS
    groups = _MODE8_GROUPS
    choices_per_order = _MODE8_CHOICES_PER_ORDER
    target_account_id = _MODE8_TARGET_ACCOUNT_ID
    tested = 0

    # A global candidate index consists of a group-permutation index followed
    # by an index into that permutation's Cartesian word-product.  A chunk can
    # cross permutation boundaries, so handle each covered segment in turn.
    cursor = start
    while cursor < stop:
        order_index, product_start = divmod(cursor, choices_per_order)
        group_order = _nth_permutation(groups, order_index)
        group_by_position = dict(zip(unanchored_positions, group_order))
        candidate_lists = [
            fixed[pos] if pos in fixed else group_by_position[pos]
            for pos in range(1, SEED_LENGTH + 1)
        ]

        segment_stop = min(stop, (order_index + 1) * choices_per_order)
        segment_length = segment_stop - cursor
        indices = _product_indices(product_start, candidate_lists)
        for offset in range(segment_length):
            words = tuple(
                candidates[index]
                for candidates, index in zip(candidate_lists, indices)
            )
            tested += 1
            if not _is_valid_12_word_checksum(words):
                pass
            else:
                phrase = " ".join(words)
                try:
                    account_id = _mode8_account_id(phrase)
                except (ValueError, OverflowError):
                    account_id = None
                if account_id == target_account_id:
                    return tested, {'phrase': phrase}

            if offset + 1 < segment_length:
                _advance_product_indices(indices, candidate_lists)

        cursor = segment_stop

    return tested, None


def search_tokenlist_for_address(filename, target_address, processes=1,
                                 batch_size=1024):
    spec = load_position_tokenlist(filename)
    if not spec:
        return []

    fixed = spec["fixed"]
    unanchored_positions = spec["unanchored_positions"]
    groups = spec["groups"]

    choices_per_order = 1
    for words in fixed.values():
        choices_per_order *= len(words)
    for group in groups:
        choices_per_order *= len(group)

    permutation_count = math.factorial(len(groups))
    total = permutation_count * choices_per_order

    try:
        target_account_id = _decode_xrp_account_id(target_address)
    except ValueError as exc:
        print(f"\n✗ Invalid XRP classic address: {exc}")
        return []

    print(f"\nLoaded tokenlist: {filename}")
    print("Anchored positions:")
    print("  " + (" | ".join(
        f"{pos}:{len(fixed[pos]):,}" for pos in sorted(fixed)
    ) if fixed else "none"))
    print(
        "Unanchored positions (ONLY these positions permute): "
        + ", ".join(map(str, unanchored_positions))
    )
    print("Unanchored candidate groups:")
    print("  " + " | ".join(
        f"group {i+1}:{len(group):,}" for i, group in enumerate(groups)
    ))
    print(f"Group permutations: {permutation_count:,}")
    print(f"Candidate space: {total:,}")
    print(f"Searching for XRP address: {target_address}")
    print("Press Ctrl+C to stop scanning at any time\n")

    tracker = ProgressTracker("Tokenlist Address Search", total)
    tracker._render()
    matches = []

    try:
        candidate_batch = max(1, batch_size)
        tasks = (
            (start, min(start + candidate_batch, total))
            for start in range(0, total, candidate_batch)
        )
        with mp.Pool(
            processes=processes,
            initializer=_init_mode8_worker,
            initargs=(fixed, unanchored_positions, groups,
                      choices_per_order, target_account_id),
        ) as pool:
            try:
                for tested, match in pool.imap_unordered(
                        _tokenlist_cartesian_batch_worker, tasks, chunksize=1):
                    tracker.update(tested)
                    if match:
                        match['address'] = target_address
                        matches.append(match)
                        print("\n✓ Found target address match!")
                        print(f"Seed: {match['phrase']}")
                        print(f"Address: {target_address}\n")
                        pool.terminate()
                        break
            except KeyboardInterrupt:
                pool.terminate()
                raise
        tracker.finish()
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")

    return matches

def descramble_seed(scrambled_words, wordlist):
    if len(scrambled_words) != SEED_LENGTH:
        print(f"\n✗ Invalid: Seed phrase must contain exactly {SEED_LENGTH} words")
        return []
    
    tracker = ProgressTracker("Descrambling")
    valid_phrases = []
    mnemo = Mnemonic("english")
    
    print(f"Testing permutations of {len(scrambled_words)} words...")
    
    try:
        for perm in itertools.permutations(scrambled_words):
            phrase = " ".join(perm)
            if mnemo.check(phrase):
                valid_phrases.append(phrase)
                print(f"\nFound valid phrase: {phrase}")
            tracker.update()
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
    return valid_phrases

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║     🌱 Advanced Seed Recovery Tool 🌱     ║
    ║           [ XRP Seed Manager ]            ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)

def print_menu():
    menu = """
    🔍 Available Operations:
    
    [1] 🔄 Scan positions for address match
    [2] 🎯 Search by address pattern
    [3] 🧩 Find missing words
    [4] ✓ Validate seed phrase
    [5] 📋 Display addresses
    [6] 🔀 Descramble seed
    [7] ✨ Generate new seed
    [8] 📄 Search fixed position tokenlist for XRP address
    """
    print(menu)

def print_progress_bar(percentage):
    bar_length = 30
    filled = int(bar_length * percentage)
    bar = '█' * filled + '░' * (bar_length - filled)
    return f'[{bar}] {percentage*100:.1f}%'

def generate_new_seed():
    mnemo = Mnemonic("english")
    # BIP-39 entropy strength 128 generates exactly 12 words.
    new_seed = mnemo.generate(strength=128)
    address = derive_xrp_address(new_seed)
    
    print("\n✨ Generated New Seed Phrase:")
    print(f"{new_seed}")
    print(f"\n📍 Corresponding XRP Address ({XRP_DERIVATION_PATH}):")
    print(f"{address}")
    
    with open('new_seed.txt', 'w') as f:
        f.write(
            f"Seed Phrase:\n{new_seed}\n\n"
            f"XRP Address ({XRP_DERIVATION_PATH}):\n{address}"
        )
    print("\n💾 Saved to 'new_seed.txt'")
    return new_seed


def parse_args():
    parser = argparse.ArgumentParser(description="12-word XRP seed recovery tool")
    parser.add_argument(
        "--processes", "-p", type=int, default=max(1, os.cpu_count() or 1),
        help="worker processes for modes 1-4 and 8 (default: all logical CPU cores)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=1024,
        help="candidate combinations per multiprocessing task for modes 1-4 (default: 1024)"
    )
    parser.add_argument(
        "--mode8-batch-size", type=int, default=1024,
        help="candidate combinations per Mode 8 task (default: 1024)"
    )
    args = parser.parse_args()
    if args.processes < 1:
        parser.error("--processes must be at least 1")
    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")
    if args.mode8_batch_size < 1:
        parser.error("--mode8-batch-size must be at least 1")
    return args


def main():
    args = parse_args()
    clear_screen()
    print_banner()
    print_menu()
    
    mode = input("\n📎 Enter mode number (1-8): ").strip()
    mnemo = Mnemonic("english")
    wordlist = tuple(mnemo.wordlist)
    print(f"\n⚙️ Multiprocessing workers: {args.processes}")
    print(f"📦 Candidate batch size: {args.batch_size:,}")

    if mode == "1":
        print(f"\n🔤 Enter {SEED_LENGTH} positions using 1-5 ? placeholders:")
        seed_words = input().strip().lower().split()
        if len(seed_words) != SEED_LENGTH:
            print(f"\n⚠️ Input contains {len(seed_words)} words. Please provide exactly {SEED_LENGTH} words.")
            return
            
        print("🎯 Enter target XRP classic address:")
        target_address = input().strip()
        
        matches = scan_positions_for_address(
            seed_words, target_address, wordlist, args.processes, args.batch_size
        )
        if matches:
            print(f"\nFound {len(matches)} matching combinations!")
            with open('position_matches.txt', 'w') as f:
                for i, match in enumerate(matches, 1):
                    changes = "\n".join(
                        f"Position {position}: ? -> {replacement}"
                        for position, replacement in match['replacements']
                    )
                    output = (f"\nMatch {i}:"
                              f"\n{changes}"
                              f"\nXRP address: {match['address']}"
                              f"\nSeed phrase:\n{match['phrase']}")
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'position_matches.txt'")
        else:
            print("\nNo matching combinations found")

    elif mode == "2":
        print("\nEnter known words, or a 12-position phrase using ? for each missing word:")
        partial_words = input().strip().lower().split()
        print("Enter address pattern to find:")
        target_pattern = input().strip()
        
        matches = search_address_pattern(
            partial_words, target_pattern, wordlist, args.processes,
            args.batch_size
        )
        if matches:
            print(f"\nFound {len(matches)} matching combinations!")
            with open('pattern_matches.txt', 'w') as f:
                for i, match in enumerate(matches, 1):
                    output = f"\nMatch {i}:\nAddress: {match['address']}\nSeed: {match['phrase']}"
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'pattern_matches.txt'")
        else:
            print("\nNo matches found")

    elif mode == "3":
        print("\nEnter known words, or a 12-position phrase using ? for each missing word:")
        known_words = input().strip().lower().split()
        if "?" in known_words:
            num_missing = None
            print(f"Detected {known_words.count('?')} missing word placeholder(s).")
        else:
            print("Enter number of omitted trailing words:")
            try:
                num_missing = int(input().strip())
            except ValueError:
                print("Missing-word count must be a whole number")
                return
        
        valid_phrases = find_missing_words(
            known_words, num_missing, wordlist, args.processes, args.batch_size
        )
        if valid_phrases:
            print(f"\nFound {len(valid_phrases)} valid combinations!")
            with open('missing_words.txt', 'w') as f:
                for i, phrase in enumerate(valid_phrases, 1):
                    output = f"\nOption {i}:\n{phrase}"
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'missing_words.txt'")
        else:
            print("\nNo valid combinations found")

    elif mode == "4":
        print(f"\nEnter your {SEED_LENGTH}-word seed phrase:")
        words = input().strip().lower().split()
        if len(words) == SEED_LENGTH:
            with mp.Pool(processes=args.processes, initializer=_init_worker) as pool:
                is_valid, address, error = pool.apply(_validate_seed_worker, (words,))
            if is_valid:
                print("\n✓ Valid seed phrase")
                if address:
                    print(f"XRP Address ({XRP_DERIVATION_PATH}): {address}")
                elif error:
                    print(f"Note: Valid seed but couldn't generate XRP address: {error}")
            else:
                print("\n✗ Invalid seed phrase")
        else:
            print(f"Seed phrase must contain exactly {SEED_LENGTH} words")

    elif mode == "5":
        print(f"\nEnter your {SEED_LENGTH}-word seed phrase:")
        words = input().strip().lower().split()
        if len(words) == SEED_LENGTH:
            if validate_seed(words):
                display_addresses(" ".join(words))
        else:
            print(f"Seed phrase must contain exactly {SEED_LENGTH} words")

    elif mode == "6":
        print(f"\n🔤 Enter exactly {SEED_LENGTH} scrambled words:")
        scrambled = input().strip().lower().split()
        if len(scrambled) != SEED_LENGTH:
            print(f"\n⚠️ Input contains {len(scrambled)} words. Please provide exactly {SEED_LENGTH} words.")
            return
        
        valid_phrases = descramble_seed(scrambled, wordlist)
        if valid_phrases:
            print(f"\nFound {len(valid_phrases)} valid combinations!")
            with open('descrambled.txt', 'w') as f:
                for i, phrase in enumerate(valid_phrases, 1):
                    output = f"\nOption {i}:\n{phrase}"
                    print(output)
                    f.write(output + "\n")
            print("\nResults saved to 'descrambled.txt'")
        else:
            print("\nNo valid combinations found")

    elif mode == "7":
        generate_new_seed()

    elif mode == "8":
        print(f"⚡ Mode 8 optimized batch size: {args.mode8_batch_size:,}")
        print("\n📄 Enter tokenlist filename [tokenlist.txt]:")
        tokenlist_filename = input().strip() or "tokenlist.txt"
        print("🎯 Enter target XRP classic address:")
        target_address = input().strip()

        matches = search_tokenlist_for_address(
            tokenlist_filename, target_address, args.processes,
            args.mode8_batch_size
        )
        if matches:
            with open("tokenlist_matches.txt", "w") as f:
                for i, match in enumerate(matches, 1):
                    output = (
                        f"Match {i}:\n"
                        f"XRP address: {match['address']}\n"
                        f"Seed phrase:\n{match['phrase']}\n"
                    )
                    print("\n" + output)
                    f.write(output + "\n")
            print("Results saved to 'tokenlist_matches.txt'")
        else:
            print("\nNo matching combinations found")
    else:
        print("Invalid mode number")
        print("Please try one of the listed options or use 'python xrprecover.py -h' for help")

if __name__ == "__main__":
    main()
