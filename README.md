# XRP Seed Recovery Tool

A multiprocessing Python utility for recovering and validating 12-word BIP39 seed phrases associated with XRP Ledger classic addresses.

## Important Warning

Use this program only with wallets that you own or are explicitly authorized to recover.

Never upload or share any of the following:

- Real seed phrases
- Private keys
- Wallet recovery files
- Token lists containing actual seed words
- XRP addresses you consider private
- Search results or saved recovery progress containing sensitive information

For maximum security, run the program on an offline computer.

## Features

The program provides several XRP seed-management and recovery operations:

1. Scan up to five marked seed positions for a matching XRP address.
2. Search for XRP addresses that match a pattern, such as the final six characters.
3. Recover missing seed words by testing valid, checksummed permutations and saving results to `missing_words.txt`.
4. Validate a 12-word BIP39 seed phrase.
5. Display the XRP address derived with the path `m/44'/144'/0'/0`.
6. Descramble a 12-word seed phrase using a provided XRP address.
7. Generate a new seed phrase and derive its XRP address with the path `m/44'/144'/0'/0`.
8. Search a token-list candidate space supplied in `tokenlist.txt`.

Depending on the selected mode, additional features may include:

- Multiprocessing across CPU cores
- Configurable process count
- Configurable batch size
- Live speed and progress reporting
- Estimated completion time
- Immediate output when a match is found
- Restart and resume support
- Audio notification upon completion
- XRP Ledger classic-address derivation

## Requirements

- Linux, Windows, or macOS
- Python 3
- A 64-bit Python installation
- Required Python packages used by the script

Check your Python version:

```bash
python3 --version
```

It is recommended to use a Python virtual environment.

## Installation

Clone the repository:

```bash
git clone https://github.com/duhghee/xrprecover.git
cd xrprecover
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows, activate it with:

```powershell
.venv\Scripts\activate
```

Install the dependencies listed in `requirements.txt`, if supplied:

```bash
python3 -m pip install -r requirements.txt
```

## Running the Program

Display command-line options:

```bash
python3 xrprecover.py --help
```

Start with the default settings:

```bash
python3 xrprecover.py
```

Run with a selected number of processes:

```bash
python3 xrprecover.py --processes 16
```

Run with a selected process count and batch size:

```bash
python3 xrprecover.py --processes 32 --batch-size 2048
```

Only use an option if it appears in the output of:

```bash
python3 xrprecover.py --help
```

## CPU Tuning

A reasonable starting point is:

```bash
python3 xrprecover.py --processes 16 --batch-size 2048
```

Increase the process count gradually while monitoring CPU temperature, memory usage, and candidates per second.

The best setting is the one that produces the highest sustained search speed—not necessarily the largest process count.

## Missing Words

Enter a question mark (?) at each unknown position when supported by the selected mode.

Example:

```text
word1 word2 ? word4 word5 ? word7 word8 word9 word10 word11 word12
```

Only marked positions should be replaced in modes configured for missing-word recovery.

## Token Lists

Token-list mode uses candidate groups assigned to seed positions. Unanchored positions should exchange candidates only with other unanchored positions.

Do not publish a token list containing a genuine or partially reconstructed seed phrase.

***  Inspired by https://github.com/d31337m3/seedy/  ***



