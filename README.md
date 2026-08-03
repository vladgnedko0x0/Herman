<div align="center">

# 🔥 GutmannShredder

**Military-grade file destruction for Windows — Gutmann method with multithreaded execution**

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square&logo=cplusplus)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://docs.microsoft.com/en-us/windows/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Build](https://img.shields.io/badge/Build-MSVC%202019%2B-purple?style=flat-square&logo=visualstudio)](https://visualstudio.microsoft.com/)

<br/>

> Permanently and irrecoverably destroys files using the **Gutmann 35-pass overwrite** algorithm.  
> Files are overwritten in memory, written back once, and renamed to their MD5 fingerprint —  
> leaving no trace of the original content or filename.

</div>

---

## 📋 Table of Contents

- [How It Works](#-how-it-works)
- [Features](#-features)
- [Performance Optimisations](#-performance-optimisations)
- [Requirements](#-requirements)
- [Build](#-build)
- [Usage](#-usage)
- [Technical Details](#-technical-details)
- [Limitations](#-limitations)

---

## 🔬 How It Works

The **Gutmann method** (Peter Gutmann, 1996) is a data sanitisation algorithm originally designed to defeat magnetic force microscopy recovery of overwritten data on HDDs.

```
┌─────────────────────────────────────────────────────────┐
│                   File: secret.docx                     │
└───────────────────────┬─────────────────────────────────┘
                        │
            ┌───────────▼────────────┐
            │  Read entire file into │
            │  memory buffer         │
            └───────────┬────────────┘
                        │
            ┌───────────▼────────────────────────────────┐
            │  Gutmann overwrite (optimised, 1 pass)      │
            │                                             │
            │  buffer[i] = random_byte ⊕ kXorMask        │
            │                                             │
            │  Mathematically equivalent to:              │
            │  • 4× random passes (Passes 1–4)            │
            │  • 29× patterned XOR passes (Passes 5–33)   │
            └───────────┬────────────────────────────────┘
                        │
            ┌───────────▼────────────┐
            │  Write buffer back     │
            │  to disk (1 I/O op)    │
            └───────────┬────────────┘
                        │
            ┌───────────▼────────────┐
            │  Rename file →         │
            │  MD5(filename+content) │
            └────────────────────────┘
```

Each byte of the original file is replaced with a pseudo-random value XORed against a precomputed mask derived from all 33 Gutmann pattern constants — making the original data unrecoverable.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Gutmann Algorithm** | Full 33-pass equivalent overwrite (4 random + 29 patterned passes) |
| **Recursive Processing** | Processes entire directory trees, including nested subdirectories |
| **Multithreaded** | Thread pool sized to CPU core count — no idle time, no thread explosion |
| **Secure Rename** | Files renamed to `MD5(path + content)` — original filename destroyed |
| **Thread-safe RNG** | Per-thread `mt19937` — no shared state, no UB, better entropy than `rand()` |
| **Single Write** | All passes computed in RAM, written to disk exactly once |

---

## ⚡ Performance Optimisations

This implementation applies several non-trivial optimisations over the naïve Gutmann approach:

### 1 — 33 passes collapsed into 1

The standard implementation iterates over the file 33 times. This one does it once.

**Proof:**
- Passes 1–4 overwrite each byte with a random value `R`. Only the last write survives → base = `R`
- Passes 5–33 XOR the buffer with fixed pattern constants `P₅ … P₃₃`
- XOR is associative and commutative:

```
R ⊕ P₅ ⊕ P₆ ⊕ … ⊕ P₃₃  =  R ⊕ kXorMask
```

**Result:** `buffer[i] = random_byte ⊕ kXorMask` — one pass, identical output.

> **Speedup:** ~33× on CPU-bound work; real-world gain depends on file size vs. CPU cache.

### 2 — Thread Pool instead of thread-per-file

| Naïve | Optimised |
|---|---|
| 1 thread per file | Fixed pool = `hardware_concurrency()` threads |
| 10 000 files = 10 000 threads | Always ≤ logical CPU count |
| OS starts swapping thread stacks | Constant memory footprint |
| Creation/destruction overhead per file | Workers reused across all files |

### 3 — Thread-local `mt19937`

`rand()` uses global shared state — calling it from multiple threads simultaneously is **undefined behaviour**. Each worker thread gets its own `mt19937` seeded from `std::random_device`, which is also statistically superior.

### 4 — Precomputed pattern constants

The original algorithm stored patterns as `std::string` binary literals and called `strtol()` in the inner loop on every byte. Here all 33 pattern values are `constexpr uint8_t[]` — zero runtime cost.

### 5 — Single I/O round-trip

Read once → transform in RAM → write once. No repeated disk seeks.

---

## 🛠 Requirements

- **OS:** Windows 10 / 11 (uses WinAPI + WinCrypt)
- **Compiler:** MSVC 2019+ or MinGW-w64 with C++17
- **Standard:** C++17 (`std::thread`, `std::atomic`, `std::filesystem`)
- **Libs:** `Crypt32.lib` (linked via `#pragma comment`)

---

## 🏗 Build

### Visual Studio

1. Create a new **Console Application** project (C++)
2. Replace the generated `.cpp` with `gutmann_shredder.cpp`
3. Set **C++ Language Standard** → `ISO C++17`
4. Build → `Ctrl+B`

### Command Line (MSVC)

```bat
cl /std:c++17 /O2 /EHsc gutmann_shredder.cpp /link Crypt32.lib
```

### MinGW-w64

```bash
g++ -std=c++17 -O2 -o gutmann_shredder gutmann_shredder.cpp -lCrypt32
```

---

## 🚀 Usage

Run the compiled executable and enter the path to the folder you want to shred:

```
> gutmann_shredder.exe

Enter path to folder: C:\Users\you\sensitive_data
```

Paths with spaces can be entered with or without surrounding quotes:

```
Enter path to folder: "C:\My Documents\To Delete"
```

**Output example:**

```
No1 Guttmann success: C:\sensitive_data\report.docx
New name: 3f2a91c84eb0d21f7a6b9c3e1d0f8a52

No2 Guttmann success: C:\sensitive_data\passwords.txt
New name: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

Done. Processed 2 file(s).
```

> ⚠️ **This operation is irreversible.** All files in the specified folder and its subdirectories will be permanently destroyed. There is no undo.

---

## 🔧 Technical Details

### Gutmann Pattern Constants

```
Pass  1– 4  Random data
Pass  5     0x55   (01010101)
Pass  6     0xAA   (10101010)
Pass  7     0x92   (10010010)
...
Pass 33     0x49   (01001001)

Cumulative XOR mask (passes 5–33): precomputed at compile time
```

### File Rename Scheme

After overwriting, each file is renamed to `MD5(filepath_string + file_content)`.  
This ensures:
- The original filename is erased from the filesystem
- The new name is deterministic for that specific overwrite result
- Collisions between different files are statistically negligible (MD5 = 128 bits)

### Thread Pool Architecture

```
main thread
    │
    ├── processDirectory()  [recursive, single-threaded]
    │       │
    │       ├── enqueue(file_1) ──► Worker Thread 0
    │       ├── enqueue(file_2) ──► Worker Thread 1
    │       ├── enqueue(file_3) ──► Worker Thread 2
    │       └── enqueue(file_N) ──► Worker Thread M
    │                              (M = hardware_concurrency)
    │
    └── ~ThreadPool()  [waits for all tasks to complete]
```

---

## ⚠️ Limitations

- **Windows only** — relies on `WinAPI` (`FindFirstFileA`, `WIN32_FIND_DATAA`) and `WinCrypt` (`CryptAcquireContext`, `CALG_MD5`)
- **SSD note** — the Gutmann method was designed for magnetic HDDs. On SSDs, wear-levelling firmware may store data in different physical cells, meaning software-level overwrites cannot guarantee complete erasure. For SSDs, hardware-level `ATA Secure Erase` or physical destruction is preferred
- **Large files** — the entire file is loaded into RAM before processing; files larger than available memory will fail
- **No logging** — processed file paths are printed to stdout only; no persistent log file is written

---

<div align="center">

Made with C++17 · Windows · WinCrypt · `std::thread`

</div>
