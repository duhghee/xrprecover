#!/usr/bin/env python3
"""Verify and benchmark AVX2 PBKDF2 without entering any real seed."""
import argparse
import hashlib
import json
import random
import statistics
import time
from pathlib import Path
from mnemonic import Mnemonic
from pbkdf2_native import NativePBKDF2

def timed(fn, repeats):
    results = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        results.append(time.perf_counter() - start)
    return statistics.median(results)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=2048)
    parser.add_argument("--batch-size", type=int, default=32,
                        help="Valid phrases per native call; normally about 32 per 1024 search candidates")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--enable", action="store_true",
                        help="Enable native engine only if verified and at least 10%% faster here")
    args = parser.parse_args()
    if min(args.samples,args.batch_size,args.repeats)<1:
        parser.error("Counts must be positive")
    if args.enable:
        Path(__file__).with_name("pbkdf2_backend.json").unlink(missing_ok=True)
    native = NativePBKDF2()
    mnemo = Mnemonic("english")
    rng = random.Random(3975)
    phrases = [mnemo.to_mnemonic(rng.randbytes(16)) for _ in range(args.samples)]
    # Non-multiple-of-four batches, NFKD, zero-length and HMAC block boundaries.
    edge = ["", "a", "é", "e\u0301", "x"*127, "x"*128, "x"*129, "日本語"]
    for count in (1,2,3,4,5,7,9):
        tests=(phrases+edge)[-count:]
        assert native.derive(tests)==[mnemo.to_seed(p,passphrase="") for p in tests]
    batches=[phrases[i:i+args.batch_size] for i in range(0,len(phrases),args.batch_size)]
    expected=[mnemo.to_seed(p,passphrase="") for p in phrases]
    actual=[seed for batch in batches for seed in native.derive(batch)]
    if expected != actual:
        raise SystemExit("FAIL: native output mismatch; engine not enabled")
    print(f"PASS: {len(phrases):,} phrases match current Mnemonic.to_seed; edge cases match.",flush=True)
    def scalar():
        for p in phrases:
            mnemo.to_seed(p,passphrase="")
    def vector():
        for batch in batches:
            native.derive(batch)
    scalar();vector()
    old=timed(scalar,args.repeats);new=timed(vector,args.repeats)
    speedup=old/new
    print(f"Current PBKDF2: {len(phrases)/old:,.0f} seeds/sec ({old:.3f}s)")
    print(f"AVX2 PBKDF2:   {len(phrases)/new:,.0f} seeds/sec ({new:.3f}s)")
    print(f"Speedup: {speedup:.2f}x (batch size {args.batch_size})")
    print("Single-process result; does not predict N-worker scaling.")
    if args.enable:
        config=Path(__file__).with_name("pbkdf2_backend.json")
        enabled=speedup>=1.10
        config.write_text(json.dumps({"enabled":enabled,"verified":True,"speedup":speedup,
             "library_sha256":hashlib.sha256(Path(__file__).with_name("libpbkdf2_avx2.so").read_bytes()).hexdigest()},indent=2)+"\n")
        print("Native backend ENABLED." if enabled else "Gain below 10%; reference backend retained.")
if __name__=="__main__":
    main()
