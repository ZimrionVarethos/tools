# Universal & Rust Core Forensics Suite (`core/`, `bin/`)

Suite alat analisis forensik universal dan engine biner berkinerja tinggi berbasis **Rust (⚡)** dan **Python**. Dirancang untuk membedah **SEMUA format file artefak investigasi** (`.dmp`, `.raw`, `.pcap`, `.pcapng`, `.ad1`, `.e01`, `.img`, `.bin`, `.exe`, `.zip`, `.pdf`, `.png`, dll.) dengan zero-copy memory mapping (`memmap2`) dan komputasi paralel SIMD multi-core (`rayon`).

---

## 🧭 Daftar Isi
1. [Daftar Tools & Arsitektur Mesin](#1-daftar-tools--arsitektur-mesin)
2. [Syntax & Contoh Penggunaan](#2-syntax--contoh-penggunaan)
   - [globalscan2 (Rust Universal Scanner & Flag Hunter)](#a-globalscan2-rust-universal-scanner)
   - [strings2 (Rust Forensic Strings & Context Search)](#b-strings2-rust-forensic-strings--regex-search)
   - [binwalk2 (Rust SIMD Signature & Firmware Carver)](#c-binwalk2-rust-simd-signature-carver)
   - [memcarve (Rust Universal Raw Memory Carver)](#d-memcarve-rust-raw-memory-carver)
   - [volrust (Rust Volatility 3 Engine)](#e-volrust-rust-volatility-3-engine)
   - [globalscan (Python Legacy Scanner)](#f-globalscan-python-legacy-scanner)
3. [Cara Menjalankan di WSL Ubuntu & Windows](#3-cara-menjalankan-di-wsl-ubuntu--windows)

---

## 1. Daftar Tools & Arsitektur Mesin

| Tool / Binary | Bahasa | Kecepatan | Deskripsi & Kemampuan Forensik |
| :--- | :---: | :---: | :--- |
| **`globalscan2`** | **Rust ⚡** | ~100x | **Universal High-Speed Scanner**: Zero-copy parallel hashing (MD5, SHA-1, SHA-256), perhitungan Shannon entropy, CTF flag regex hunter, deteksi token sensitif (AWS, GitHub, Discord), dan auto single-byte XOR brute-force (`0x01`..`0xFF`). |
| **`strings2`** | **Rust ⚡** | ~50x | **Forensic Strings & Search Engine**: Ekstraksi string ASCII & UTF-16LE ultra-cepat, pencarian substring `-s`, regex engine `-r`, offset byte printing `-o`, dan context lines `-C` untuk melihat lingkungan sekitar string target. |
| **`binwalk2`** | **Rust ⚡** | ~80x | **SIMD Firmware & Binary Signature Carver**: Pemindaian signature file biner dalam hitungan milidetik, auto-ekstraksi langsung ke direktori tujuan (`-e -o <dir>`). |
| **`memcarve`** | **Rust ⚡** | Instant | **Raw Memory Carver & Reverse-Page Assembler**: Ekstraksi biner (DEX, ELF, PE, ZIP) dari raw RAM gigabyte, auto-deteksi alokasi halaman LIFO *reverse order* vs *forward linear*, verifikasi checksum (Adler32, SHA-1), dan page context hexdump. |
| **`volrust`** | **Rust ⚡** | 20x - 500x | **Volatility 3 Engine in Rust (`vol-rs`)**: Porting native tanpa bottleneck Python interpreter untuk plugin `windows.pslist`, `windows.malfind`, `windows.netscan`, `windows.filescan`. |
| **`globalscan`** | **Python** | Baseline | **Universal File Scanner**: Skrip pemindai serbaguna original berbasis Python (tetap dipertahankan penuh). |

---

## 2. Syntax & Contoh Penggunaan

### A. `globalscan2` – Rust Universal Scanner

Pemindaian menyeluruh, ekstraksi hash, entropi data, dan pemburu flag CTF multi-thread.

```bash
# 1. Pemindaian lengkap pada memory dump:
globalscan2 memory.raw

# 2. Hanya tampilkan flag CTF yang ditemukan:
globalscan2 capture.pcapng --flags-only

# 3. Cari flag dengan prefix khusus:
globalscan2 disk.raw -p "CTF{"

# 4. Ekspor seluruh hasil temuan:
globalscan2 evidence.bin --export-all
```

---

### B. `strings2` – Rust Forensic Strings & Regex Search

Ekstraksi string ASCII & Unicode (UTF-16LE) super cepat dengan pencarian berbasis regex dan konteks baris:

```bash
# 1. Ekstraksi seluruh string dengan panjang minimum 6 karakter:
strings2 memory.raw -n 6

# 2. Cari string spesifik dengan 3 baris konteks sebelum dan sesudah:
strings2 -s "api/v1" capture.pcap -C 3

# 3. Cari pola flag CTF menggunakan regular expression:
strings2 -r "flag{[^}]+}" memory.raw

# 4. Tampilkan physical byte offset dari setiap string yang ditemukan:
strings2 -s "password" disk.img -o
```

---

### C. `binwalk2` – Rust SIMD Signature Carver

Pemindaian magic bytes dan ekstraksi embedded file:

```bash
# 1. Pindai signature biner yang terkandung di dalam file:
binwalk2 firmware.bin

# 2. Ekstrak otomatis semua biner yang ditemukan ke folder:
binwalk2 firmware.bin -e -o ./carved_output
```

---

### D. `memcarve` – Rust Raw Memory Carver

Membedah memory dump raw dengan deteksi alokasi halaman terbalik (LIFO reverse order):

```bash
# 1. Carve biner DEX yang memuat string target:
memcarve scan chall.raw DEX "api/v1" --extract ./carved_dex

# 2. Scan semua header biner yang memuat kata kunci:
memcarve scan chall.raw -a "flag" --extract ./carved_all

# 3. Tampilkan kamus signature header:
memcarve dict

# 4. Inspeksi context hexdump halaman memori di sekitar offset:
memcarve context chall.raw --offset 0x00a12000
```

---

### E. `volrust` – Rust Volatility 3 Engine

Eksekusi plugin memory triage tanpa hambatan performa:

```bash
# Daftar proses Windows aktif:
volrust -f memory.raw windows.pslist

# Deteksi memory injection (RWX code injection):
volrust -f memory.raw windows.malfind

# Analisis koneksi jaringan aktif:
volrust -f memory.raw windows.netscan
```

---

### F. `globalscan` – Python Legacy Scanner

Versi Python original:

```bash
globalscan DbgInfo.DMP
globalscan capture.pcapng --flags-only
```

---

## 3. Cara Menjalankan di WSL Ubuntu & Windows

### Via Alias Global (WSL / Linux)
```bash
# Setup alias sekali di awal:
bash /mnt/d/tools/install_alias.sh
source ~/.bashrc

# Jalankan perintah langsung:
globalscan2 cute.DMP
strings2 -s "api/v1" wire.pcap -C 2
binwalk2 firmware.bin -e -o ./carved
memcarve scan chall.raw DEX "api/v1"
volrust -f memory.raw windows.pslist
```

### Via Master Dispatcher (`tools.py`)
```bash
python3 tools.py core globalscan2 cute.DMP
python3 tools.py core strings2 -s "api/v1" wire.pcap
python3 tools.py core binwalk2 firmware.bin -e -o ./carved
python3 tools.py core memcarve scan chall.raw DEX "api/v1"
python3 tools.py core volrust -f memory.raw windows.pslist
```
