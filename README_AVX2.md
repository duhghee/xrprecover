# XRPRECOVER AVX2 PBKDF2 COMPONENT
# Linux x86-64 with AVX2; intended for AMD & intel CPU's supporting AVX2. 
# Check your model.

# Extract this entire folder. Run commands from the extracted folder.
        Keep its xrprecover.py, pbkdf2_native.py, C source and benchmark together.

# 1. Activate a virtual environment and install Python dependencies:
        python -m pip install -r requirements.txt

# 2. Build locally (GCC required):
        python3 build_native.py
   
#  If GCC is absent on Ubuntu: 
        sudo apt install build-essential

# 3. Verify and benchmark on YOUR machine:
        python3 benchmark_pbkdf2.py --enable

   Synthetic phrases only. No real seed is requested.
   The benchmark compares all outputs against Mnemonic.to_seed, tests edge
   cases, and enables AVX2 only if it is at least 10% faster.
   Rebuilding removes the enable flag, so each new build must be benchmarked.
   Verification or speed failure leaves the reference backend in use.

# 4. Run Mode 2:
        python3 xrprecover.py --processes N --batch-size 1024

   * Look for: PBKDF2 backend: AVX2 (verified benchmark)
   * Address-checking modes can use the backend when their candidate
     evaluation path enables it; modes generating checksum-only output
     need no PBKDF2.
   * Missing/unverified component uses the reference implementation.

# 5. Compare recovery speed with the reference, using identical inputs:
        python3 xrprecover.py --processes N --batch-size 1024 --pbkdf2-backend reference
        python3 xrprecover.py --processes N --batch-size 1024 --pbkdf2-backend auto

   * Run one at a time, repeat, compare final progress speeds. 
   * The single-process benchmark cannot establish multi-worker gains. 
   * AVX2 also uses CPU resources.
   * For example: compare 32 workers if 64 workers scales poorly.

# What this implements:

- Four independent SHA512 computations in AVX2 lanes.
- Precomputed HMAC ipad/opad states.
- Exactly 2048 PBKDF2-HMAC-SHA512 iterations and 64 output bytes.
- NFKD normalization and empty BIP39 passphrase, matching current xrprecover.
- English 12-word phrases fit within the supported 128-byte native key size. Longer inputs use the reference PBKDF2 function.
- Valid phrases are collected within each search batch; native PBKDF2 processes them together, before unchanged XRP derivation/address matching.
- Native outputs are self-tested on every process load. The shared-library hash must match the local successful benchmark's configuration.

* The native implementation is independently tested, but has not had a third-party cryptographic audit. 
* It does not change the wallet path or iteration count.
* No compiled binary or enabled configuration is shipped: build and benchmark locally before it is used.

# Measured on the development host (AMD EPYC 9V74, Linux):

- PBKDF2: 1,212 -> 2,660 seeds/sec, 2.20x, 2048 phrases, 5 repeats, batch 64.
- Mode 2 worker: 17,099 -> 31,217 candidates/sec, 1.83x, 4096 candidates,
  batch 1024, median of 3 repeats.
- 2048 synthetic mnemonic outputs matched reference.
- Variable batch sizes, Unicode normalization, 127/128/129-byte boundary cases.
- Variable passwords/batches passed undefined-behavior sanitizer checks.
- Modes 1/2 recovery matched reference using real spawn multiprocessing.

* These measurements are NOT a forecast for 64 processes.

Windows users: the optional AVX2 shared-library build is not supported
by build_native.py. Use the reference backend on Windows.
