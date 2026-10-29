# XRPRecover

**Offline-oriented XRP classic-address recovery utilities for 12-word English BIP-39 mnemonics.**

The project provides **15 modes** for mnemonic validation, address derivation,
fixed-position missing/wrong-word search, tokenlist processing, and scrambled
word-order search. Modes **14** and **15** replace one or two words respectively
**and permute all twelve positions**. Only use this software for wallets you own
or are explicitly authorized to recover.

> **Important:** Recovery phrases are secrets. This software does not access
> the XRP Ledger, move funds, or guarantee a recovery. Exhaustive searches for
> Modes 14 and 15 may be computationally infeasible.

## Install (Windows CMD)

```cmd
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python xrprecover.py
```

## Install (Ubuntu 24.04)

```bash
sudo apt update
sudo apt install -y python3-venv python3-tk build-essential
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python xrprecover.py
```

The CLI may also be run non-interactively:

```text
python xrprecover.py --mode 15 --mnemonic "twelve BIP39 words" --address "r..."
```

Replace the example words and address with values **only in a secure local
terminal**; command-line arguments can be captured by shell history and process
inspection. For sensitive material, prefer the interactive prompts in a trusted,
offline environment.

## Mode overview

| Modes | Purpose |
| --- | --- |
| 1 | One wrong word, fixed positions |
| 2-3 | Address pattern and missing trailing words |
| 4-5 | Mnemonic validation and XRP address derivation |
| 6-7 | Word-order descramble and new mnemonic generation |
| 8-9 | Missing positions and address-matched tokenlists |
| 10-11 | Two or three wrong words, fixed positions |
| 12-13 | Valid tokenlist phrases and address-matched trailing words |
| **14** | **One wrong word, all-position permutations** |
| **15** | **Two wrong words, all-position permutations** |

Both Modes 14 and 15 require twelve **distinct, valid English BIP-39 input
words** and a target classic `r...` XRP address. They replace the specified
number of words with words not already present in the input. No checkpoint or
resume mechanism is implemented.

## Full documentation

- [Readme.md](Readme.md) — all modes, options, outputs and limitations
- [README_tokenlist.md](README_tokenlist.md) — tokenlist GUI and file format
- [README_AVX2.md](README_AVX2.md) — optional, locally built Linux AVX2 PBKDF2
- [github-ruleset.json](github-ruleset.json) — optional default-branch protection ruleset payload
- [github-description.txt](github-description.txt) — repository About description

Python packages are listed in [`requirements.txt`](requirements.txt).
The native accelerator is **optional** and **Linux x86-64 only**. Do not upload
private recovery results to GitHub.
