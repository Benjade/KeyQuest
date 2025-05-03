# KeyQuest

**KeyQuest** is a high-performance C++ tool designed to tackle challenging Bitcoin cryptographic puzzles on CPU, such as the 1000 Bitcoin Puzzle (see [~1000 BTC Bitcoin Challenge](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx)). It performs a hybrid search combining deterministic range scanning with random suffix exploration to find a private key matching a given address.

![KeyQuest](https://decraene.net/images/keyquest/keyquest.jpg "KeyQuest")
*_The image represents a search on 256 virtual threads, the actual CPU count being 6._
## Prerequisites

- A modern Linux distribution
- A C++17-capable compiler (e.g., `g++`)
- GNU Make
- OpenSSL and build development headers:
  ```bash
  sudo apt-get update
  sudo apt-get install libssl-dev
  sudo apt install build-essential linux-libc-dev
  ```
- Email software for notifications (choose one):
- 
  *(Update the email address in `KeyQuest.cpp` before compiling.)*
  
  - **msmtp**:
    ```bash
    sudo apt-get install msmtp
    ```
    Configure SMTP settings:
    ```bash
    sudo nano /etc/msmtprc
    ```
    ```bash
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
    ```
    Ensure `msmtp` is set as the sendmail alternative or adjust `MAIL_PROGRAM` in the code.

    Test email sending:
    ```bash
    echo "This is a test." | msmtp your@email.com
    ```
  - **sendmail** (alternative):
    ```bash
    sudo apt-get install sendmail
    ```
    Uses `/usr/sbin/sendmail` by default. Configure sendmail per your distribution's docs.

    ![KeyQuest mail](https://decraene.net/images/keyquest/mail.jpg "KeyQuest mail")

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
./KeyQuest
```

Fast test puzzle 70 using:

19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR Range: 349b84b6431a000000:349b84b6431affffff Suffix: 6

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

This program uses several optimized routines by Jean‑Luc Pons and Dookoo2, adapted from [VanitySearch](https://github.com/JeanLucPons/VanitySearch) and [Cyclone](https://github.com/Dookoo2/Cyclone).

## Donation

If you find **KeyQuest** useful, consider support:

```
1Bitcoinfr7ZVB1cFVgLJJcweVt8JR2Z3o
```

## Changelog 3 march 2025

### 1. Configuration & Command-Line Interface

- **Dynamic batch size**  
  - **Old:** `POINTS_BATCH_SIZE` fixed at 512.  
  - **New:** `g_pointsBatchSize` defaults to 512 and can be overridden with `-b <batchSize>`.

- **Enhanced config loading**  
  - Retains `-c` to load `config.txt`, but now prompts more interactively for encryption, thread count, address, range and random-hex count, with an option to save.

- **Full-random mode support**  
  - **Old:** hybrid mode required `randomHexCount > 0`.  
  - **New:** entering `0` activates “full-random” suffix generation across the entire range (`g_fullRandomMode`).

---

### 2. Search Modes & Suffix Generation

- **Hybrid vs. full-random**  
  - New flag `g_fullRandomMode` automatically set when `randomHexCount == rangeLength`, allowing seamless switch between suffix-per-prefix and pure random.

- **Flexible suffix length**  
  - Suffix generation now handles any length up to the full range hex width.

---

### 3. Performance & Batching

- **Pre-computed ECC points**  
  - **Old:** always 512 pre-computed points.  
  - **New:** pre-computes exactly `g_pointsBatchSize` for better memory use and cache locality.

- **Adaptive hashing buffers**  
  - SHA256/RIPEMD-160 batches sized by `HASH_BATCH_SIZE` and `g_pointsBatchSize`, replacing giant static arrays with `std::array`/`std::vector`.

- **Modern alignment & containers**  
  - Uses `std::vector`, `std::array`, `alignas`, and `thread_local` for RNG, vector math, and batch buffers.

---

### 4. Display & Statistics

- **Unified summary box**  
  - Combines speed, total tested, total combos, percent progress, restarts, and elapsed time into one scrolling box.

- **Optional thread-progress view**  
  - Toggle per-thread key previews with `g_showThreadProgress`.

- **Reduced mutex contention**  
  - Throttles UI updates via `kREFRESH_DELAY` to minimize lock overhead.

---

### 5. Email & Encryption

- **Streamlined encryption prompt**  
  - If encryption is enabled in config, prompt for passphrase up front.

- **Same AES-256-CBC + PBKDF2 flow**  
  - Retains `openssl enc -aes-256-cbc -pbkdf2` but with cleaner file-cleanup logic.

- **HTML email template unchanged**  
  - Presentation and sending via `msmtp` or `sendmail` remain identical.

---

### 6. Code Modernization & Maintenance

- **Removed redundancies**  
  - Dropped oversized static buffers; replaced with STL algorithms (`std::fill_n`, `std::reverse`).

- **C++11+ idioms**  
  - Widespread use of `std::atomic`, `std::mutex`, `std::thread`, `std::ostringstream`, and range-based loops.

- **Improved input validation**  
  - Validates hex-range formatting, suffix count, and prompts user clearly on errors.
