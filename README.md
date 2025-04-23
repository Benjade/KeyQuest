<!--
**Markdown Basics**

# Heading 1
## Heading 2
**Bold text**
*Italic text*
`Inline code`
```bash
Code block
```
- Unordered list
1. Ordered list
[Link text](https://example.com)
-->

# KeyQuest

**KeyQuest** is a high-performance C++ tool designed to tackle challenging Bitcoin cryptographic puzzles, such as the 1000 Bitcoin Puzzle (see (https://privatekeys.pw/puzzles/bitcoin-puzzle-tx)). It performs a hybrid search combining deterministic range scanning with random suffix exploration to find a private key matching a given address.

## Prerequisites

- A modern Linux distribution
- A C++17-capable compiler (e.g., `g++`)
- GNU Make
- OpenSSL development headers:
  ```bash
  sudo apt-get update
  sudo apt-get install libssl-dev
  ```
- Email software for notifications (choose one):
  - **msmtp**:
    ```bash
    sudo apt-get install msmtp
    ```
    Configure SMTP settings in your home directory:
    ```bash
    cat <<EOF > ~/.msmtprc
    defaults
    auth           on
    tls            on
    tls_trust_file /etc/ssl/certs/ca-certificates.crt
    logfile        ~/.msmtp.log

    account        default
    host           smtp.example.com
    port           587
    user           your_username
    password       your_password
    from           your_email@example.com
    EOF
    chmod 600 ~/.msmtprc
    ```
    Ensure `msmtp` is set as the sendmail alternative or adjust `MAIL_PROGRAM` in the code.

  - **sendmail** (alternative):
    ```bash
    sudo apt-get install sendmail
    ```
    Uses `/usr/sbin/sendmail` by default. Configure sendmail per your distribution's docs.

## Installation

Clone the repository and build the executable:

```bash
git clone https://github.com/Benjade/KeyQuest.git
cd KeyQuest
make
```

This produces the `KeyQuest` binary in the project root.

## Usage

Run the program and follow the interactive prompts:

```bash
./KeyQuest [-c]
```

- **`-c`**: skip the config-load prompt if `config.txt` exists

1. **Load config**: choose to load saved settings from `config.txt`.
2. **Encryption**: opt to encrypt the result file (`keyfound.txt`) if a key is found.
3. **Threads**: specify the number of OpenMP threads (default is number of CPU cores).
4. **Target address**: enter a Base58 Bitcoin address or raw hash160 hex string.
5. **Search range**: provide a hex range in the form `<start>:<end>` for sequential scanning.
6. **Random suffix**: set the number of random hex digits for suffix sampling (Hybrid mode).
7. **Thread progress display**: optionally hide per-thread status output.

During execution, KeyQuest displays live statistics (Mkeys/s, progress, restarts) and per-thread progress in a full-screen terminal. When a matching key is found, an HTML email is sent (via `msmtp` or `sendmail`), and the result is written to `keyfound.txt` (encrypted if enabled).

## Features

- **Hybrid search**: combines sequential prefix scanning and random suffix sampling for exhaustive coverage.
- **Multi-threaded**: leverages OpenMP; configurable thread count with optional dynamic adjustment (`OMP_DYNAMIC`).
- **Live statistics**: displays speed (Mkeys/s), progress percentage, total restarts, and per-thread status.
- **Email alerts**: high-priority HTML notification on key discovery.
- **Optional encryption**: AES-256-CBC encryption of result file with passphrase protection.
- **Config persistence**: save and reload settings via `config.txt` for repeatable runs.

## Optimizations

- **AVX2-accelerated hashing**: batch SHA-256 and RIPEMD-160 routines (`sha256_avx2.h`, `ripemd160_avx2.h`).
- **Batch EC operations**: precomputed point tables and simultaneous multiple-point (BSGS) arithmetic.
- **Lock-free counters**: atomic updates minimize overhead in hot loops.
- **Minimal allocations**: thread-local buffers and reuse to reduce latency.
- **Alternate-screen I/O**: non-blocking stats thread updates the terminal without flicker.

## Third-Party Code

This program uses several optimized BSGS routines by Jean‑Luc Pons, adapted from [VanitySearch](https://github.com/JeanLucPons/VanitySearch).

## Donation

If you find **KeyQuest** useful, consider supporting development:

```
1Bitcoinfr7ZVB1cFVgLJJcweVt8JR2Z3o
```

