# Windows Memory Dump (DMP) Forensics Suite Documentation

Suite alat analisis memori proses dan *crash dump* Windows (**`.dmp`**, **`.raw`**, **`.bin`**) berbasis **Pure Python** berkinerja tinggi. Mampu membaca struktur internal Windows Minidump, merekonstruksi lingkungan proses (*Process Environment Block* / PEB), memetakan modul biner & library (.exe, .dll), mendeteksi injeksi payload memori (RWX), memburu **CTF Flags** (ASCII, UTF-16LE, Base64), serta melakukan dumping biner target dan segmen memori tertentu (**`dmpdump`**) langsung ke disk tanpa ketergantungan GUI debugger.

---

##  Daftar Isi
1. [Daftar Tools & Kegunaan](#1-daftar-tools--kegunaan)
2. [Syntax & Contoh Menjalankan Tools](#2-syntax--contoh-menjalankan-tools)
   - [dmpscan (Full Automated Memory Dump Triage)](#a-dmpscan--full-automated-memory-dump-triage)
   - [dmpdump (Targeted Memory Range & Module Dumper)](#b-dmpdump--targeted-memory-range--module-dumper)
   - [dmppeb (Process Reconnaissance & Environment Variables)](#c-dmppeb--process-reconnaissance--environment-variables)
   - [dmpmodules (Loaded Executables & DLLs Matrix)](#d-dmpmodules--loaded-executables--dlls-matrix)
   - [dmpflags (In-Memory Deep Flag Hunter)](#e-dmpflags--in-memory-deep-flag-hunter)
3. [Korelasi dengan Command WinDbg](#3-korelasi-dengan-command-windbg)
4. [Cara Menjalankan di WSL Ubuntu & Windows](#4-cara-menjalankan-di-wsl-ubuntu--windows)

---

## 1. Daftar Tools & Kegunaan

| Nama Tool / Alias | Target Artefak | Deskripsi & Informasi yang Diekstrak |
| :--- | :--- | :--- |
| **`memcarve`** (Rust) | `memory.raw`, `.dmp`, `.bin` | **Universal Raw Memory Carver & Reverse-Page Assembler**: Ekstraksi biner cepat (DEX, ELF, PE, ZIP) dari raw RAM gigabyte dalam hitungan detik. Menggunakan heuristik deteksi alokasi LIFO *reverse page order* vs *forward linear* untuk merekonstruksi biner utuh tanpa korupsi byte, verifikasi checksum (Adler32, SHA-1, ELF headers), dan preview context halaman memori. |
| **`volrust`** (`vol-rs`) | `memory.raw`, `.dmp` | **Volatility 3 Engine Berbasis Rust**: Eksekusi plugin memory analysis (`pslist`, `malfind`, `netscan`, `filescan`) 20x s/d 500x lebih cepat tanpa ketergantungan interpreter Python. |
| **`dmpscan`** | `memory.dmp`, `crash.dmp` | **Full Automated Memory Triage**: Menjalankan analisis menyeluruh dalam satu perintah: ringkasan proses (PID, Nama, Arsitektur, Waktu), variabel lingkungan (PEB), daftar modul yang dimuat (`lm`), dan pemindaian flag CTF tanpa noise. Memberikan petunjuk alamat base address untuk dumping. |
| **`dmpdump`** | Target Memory / Module | **Targeted Memory & Module Dumper**: Mengekstrak biner executable (`.exe`), pustaka (`.dll`), atau rentang alamat memori virtual tertentu langsung ke disk berdasarkan **Base Address** (`-i`), **Nama Modul** (`-m`), atau otomatis **Main Executable** (`--main`). Dilengkapi kalkulasi hash MD5 dan SHA-256. |
| **`dmppeb`** | Virtual Memory Segments | **Process Environment Block (!peb)**: Rekonstruksi informasi eksekusi proses: Nama Image, Process ID (PID), Arsitektur OS (x64/x86), Versi Windows, Timestamp pembuatan proses, Command Line arguments, dan daftar variabel lingkungan (`USERNAME`, `COMPUTERNAME`, `USERPROFILE`, `APPDATA`, dll.). |
| **`dmpmodules`** | Minidump ModuleList | **Loaded Modules Matrix (lm)**: Memetakan seluruh executable dan DLL yang dimuat ke dalam memori proses beserta Base Virtual Address (`0x...`), ukuran memori (*Size*), path biner asli, dan informasi versi library. |
| **`dmpflags`** | Seluruh Committed Heap/Stack | **Deep In-Memory Flag Hunter**: Memindai seluruh halaman memori virtual untuk mencari format flag CTF (`flag{...}`, `CTF{...}`, custom prefix) dalam representasi **ASCII**, **Unicode (UTF-16LE)**, dan **Base64 encoded strings**. |

---

## 2. Syntax & Contoh Menjalankan Tools

### A. `dmpscan` – Full Automated Memory Dump Triage

Menjalankan pemindaian memori menyeluruh (PEB, Modul, dan CTF Flags).

#### Syntax Lengkap:
```bash
dmpscan <memory.dmp> [opsi]
```

#### Opsi yang Tersedia:
- `-p`, `--prefix "<prefix>"` : Prefix custom untuk pencarian flag (misal: `-p "CTF"`, `-p "htb"`).
- `-l`, `--limit <jumlah>` : Batas jumlah baris modul yang ditampilkan (default: 50).
- `--md <output.md>` : Ekspor laporan ke file Markdown.
- `--json <output.json>` : Ekspor laporan ke file JSON.
- `--export-all` : Buat laporan Markdown + JSON secara otomatis.

#### Contoh Penggunaan:
```bash
# 1. Triage otomatis seluruh isi memory dump
dmpscan DbgInfo.DMP

# 2. Cari flag dengan prefix khusus
dmpscan DbgInfo.DMP -p "FLAG{"

# 3. Ekspor seluruh temuan triage ke Markdown & JSON
dmpscan DbgInfo.DMP --export-all
```

---

### B. `dmpdump` – Targeted Memory Range & Module Dumper

Mengekstrak modul biner atau rentang memori spesifik tanpa noise.

#### Syntax Lengkap:
```bash
dmpdump <memory.dmp> [opsi target] -o <output_path>
```

#### Opsi yang Tersedia:
- `--main` : Otomatis mendeteksi dan mengekstrak modul binary executable utama proses.
- `-i`, `-a`, `--addr`, `--base <0x...>` : Base Virtual Address yang ingin didump (misal: `-i 0x7ff62fbd0000`).
- `-m`, `--module <nama_modul>` : Nama modul yang ingin diekstrak (misal: `-m DbgInfo.exe`, `-m ntdll.dll`).
- `-s`, `--size <ukuran>` : Ukuran byte yang ingin didump (hex/desimal). Jika tidak diisi, otomatis mendeteksi ukuran modul / header PE.
- `--all-modules` : Dump seluruh modul (.exe dan semua .dll) ke direktori output.
- `-o`, `--out <file_atau_folder>` : Lokasi file output tujuan atau folder output.

#### Contoh Penggunaan:
```bash
# 1. Dump binary executable utama secara otomatis:
dmpdump DbgInfo.DMP --main -o ./DbgInfo.exe

# 2. Dump berdasarkan Base Virtual Address spesifik:
dmpdump DbgInfo.DMP -i 0x7ff62fbd0000 -o ./dumped_binary.exe

# 3. Dump berdasarkan Nama Modul:
dmpdump DbgInfo.DMP -m DbgInfo.exe -o ./DbgInfo.exe
dmpdump DbgInfo.DMP -m ntdll.dll -o ./ntdll_dumped.dll

# 4. Dump rentang memori spesifik (misal: segmen .text 0x86000 byte):
dmpdump DbgInfo.DMP -i 0x7ff62fbd1000 -s 0x86000 -o ./text_section.bin

# 5. Dump seluruh modul yang dimuat ke folder ./all_modules:
dmpdump DbgInfo.DMP --all-modules -o ./all_modules/
```

---

### C. `dmppeb` – Process Reconnaissance & Environment Variables

Melihat metadata proses, path eksekusi, dan variabel lingkungan pengguna tanpa membuka debugger.

#### Syntax Lengkap:
```bash
dmppeb <memory.dmp>
# atau:
dmpscan <memory.dmp> --peb
```

#### Contoh Penggunaan:
```bash
dmppeb DbgInfo.DMP
```
* **Output yang dihasilkan:**
  * Process Name & PID
  * OS Build & Architecture
  * Creation Time UTC
  * Environment Variables (`USERNAME`, `COMPUTERNAME`, `TEMP`, dll.)

---

### D. `dmpmodules` – Loaded Executables & DLLs Matrix

Melihat seluruh modul dan pustaka yang aktif di dalam proses (ekuivalen perintah `lm` di WinDbg).

#### Syntax Lengkap:
```bash
dmpmodules <memory.dmp> [opsi]
# atau:
dmpscan <memory.dmp> --modules
```

#### Contoh Penggunaan:
```bash
# 1. Tampilkan daftar modul yang dimuat
dmpmodules DbgInfo.DMP

# 2. Tampilkan hingga 100 modul
dmpmodules DbgInfo.DMP -l 100
```

---

### E. `dmpflags` – In-Memory Deep Flag Hunter

Mencari flag CTF yang tersimpan di heap, stack, maupun data segmen proses (ASCII, UTF-16, Base64).

#### Syntax Lengkap:
```bash
dmpflags <memory.dmp> [opsi]
# atau:
dmpscan <memory.dmp> --flags-only
```

#### Contoh Penggunaan:
```bash
# 1. Cari flag standar di seluruh memori
dmpflags DbgInfo.DMP

# 2. Cari flag dengan prefix tertentu
dmpscan DbgInfo.DMP --flags-only -p "CTF{"
```

---

### F. `memcarve` – Universal Raw Memory Carver & Reverse-Page Assembler (Rust)

Carver memori raw berkinerja tinggi berbasis Rust yang dirancang khusus untuk membedah raw memory dump (Linux, Android, Windows) dengan auto-deteksi alokasi halaman LIFO *reverse order* vs *forward linear*.

#### Syntax Lengkap:
```bash
memcarve [FILE] [COMMAND] [opsi]
```

#### Perintah & Opsi Utama:
- `scan <FILE> <HEADER> "<KEYWORD>"` : Scan biner tipe tertentu (DEX, ELF, PE, ZIP) yang memuat string anchor target.
- `scan <FILE> -a "<KEYWORD>"` : Scan ke seluruh 15 signature header bawaan kamus.
- `dict` : Tampilkan kamus signature header yang didukung beserta ekstensi dan magic bytes.
- `context <FILE> --offset <OFFSET>` : Inspeksi hexdump dan pratinjau string di sekitar physical offset target.
- `carve <FILE> --offset <OFFSET> -o <DIR>` : Ekstrak biner langsung dari offset header yang diketahui.
- `-e`, `--extract <DIR>` : Folder tujuan penyimpanan file biner hasil rekonstruksi.

#### Contoh Penggunaan:
```bash
# 1. Carve biner DEX yang mengandung string target:
memcarve scan chall.raw DEX "api/v1" --extract ./carved_dex

# 2. Scan semua header biner yang memuat flag:
memcarve scan chall.raw -a "flag{" --extract ./carved_all

# 3. Tampilkan kamus signature header:
memcarve dict

# 4. Inspeksi context halaman di sekitar offset fisik:
memcarve context chall.raw --offset 0x00a12000
```

---

### G. `volrust` – High-Performance Volatility 3 Engine in Rust

Porting resmi engine Volatility 3 berbasis Rust (`vol-rs`) yang mengeksekusi plugin analisis memori 20x hingga 500x lebih cepat dibanding Python runtime tradisional.

#### Syntax Lengkap:
```bash
volrust -f <file.raw|file.dmp> <plugin> [opsi]
```

#### Contoh Penggunaan:
```bash
# 1. Daftar proses Windows aktif:
volrust -f memory.raw windows.pslist

# 2. Deteksi injeksi kode / hidden executable memory (RWX):
volrust -f memory.raw windows.malfind

# 3. Analisis koneksi jaringan aktif:
volrust -f memory.raw windows.netscan

# 4. Scanning file objek di memori:
volrust -f memory.raw windows.filescan
```

---

## 3. Korelasi dengan Command WinDbg

Jika kamu terbiasa atau ingin mencocokkan hasil analisis dengan WinDbg saat kompetisi, berikut padanan fungsinya:

| Fitur Forensik | Perintah WinDbg Manual | Perintah di Suite DMP |
| :--- | :--- | :--- |
| **Process & Environment Triage** | `!peb` | `dmppeb <file.dmp>` |
| **List Loaded Modules** | `lm` atau `lmvm <module>` | `dmpmodules <file.dmp>` |
| **Dump Executable dari Memory** | `.writemem C:\out.bin <Addr> L?<Size>` | `dmpdump <file.dmp> -i <Addr> -o <out.exe>` |
| **Search ASCII / Unicode Strings** | `s -a 0x0 L?0xffffffff "flag"`<br>`s -u 0x0 L?0xffffffff "flag"` | `dmpflags <file.dmp>` |
| **Layout & Proteksi Memori** | `!address` | `dmpscan <file.dmp>` |

---

## 4. Cara Menjalankan di WSL Ubuntu & Windows

### Via Alias Global (WSL / Linux)
```bash
# Setup alias sekali di awal:
bash /mnt/d/tools/install_alias.sh
source ~/.bashrc

# Jalankan perintah:
memcarve scan chall.raw DEX "api/v1" --extract ./out
volrust -f memory.raw windows.pslist
dmpscan DbgInfo.DMP
dmpdump DbgInfo.DMP --main -o ./DbgInfo.exe
dmpdump DbgInfo.DMP -i 0x7ff62fbd0000 -o ./DbgInfo.exe
dmppeb DbgInfo.DMP
dmpmodules DbgInfo.DMP
dmpflags DbgInfo.DMP
```

### Via Master Dispatcher (`tools.py`)
```bash
python3 tools.py dmp memcarve scan chall.raw DEX "api/v1" --extract ./out
python3 tools.py dmp volrust -f memory.raw windows.pslist
python3 tools.py dmp scan DbgInfo.DMP
python3 tools.py dmp dump DbgInfo.DMP -i 0x7ff62fbd0000 -o ./DbgInfo.exe
python3 tools.py dmp peb DbgInfo.DMP
python3 tools.py dmp modules DbgInfo.DMP
```
