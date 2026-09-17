#  Master Reverse Engineering & Assembly Suite (`assembly/`)

Suite lengkap reverse engineering, binary doctor, disassembler, dan Ghidra live companion yang dipecah secara rapi ke dalam 4 sub-modul spesifik:

```text
D:\tools\assembly\
├── ghidra/       <-- Jembatan interaktif 2 arah ke Ghidra GUI (ghidraanalyze / ghidracli)
├── exe/          <-- Windows PE Doctor & Memory-Dump Realigner (exefix / exedoctor / ghidraguide)
├── elf/          <-- Linux ELF Inspector & Header Doctor (elfdoctor / elffix)
├── binary/       <-- Multi-Arch Raw Shellcode Disassembler (disasm / shellcode / blobscan)
└── README.md     <-- Dokumentasi Master Assembly Suite
```

---

##  Sub-Modul & Daftar Perintah

### 1.  `assembly/ghidra/` — Ghidra Live Interactive Companion
* **`ghidraanalyze status`** : Cek koneksi ke Ghidra GUI & info program aktif.
* **`ghidraanalyze goto <addr>`** : **Geser kursor dan layar Ghidra GUI lo secara otomatis!**
* **`ghidraanalyze current`** : Decompile & jelaskan fungsi di posisi kursor saat ini.
* **`ghidraanalyze decompile <addr>`** : Decompile fungsi di alamat tertentu ke Pseudo-C.
* **`ghidraanalyze search <query>`** : Cari string, fungsi, atau Windows API di seluruh program.
* **`ghidraanalyze callers <addr>`** : Pohon fungsi pemanggil (Call Tree).
* **`ghidraanalyze callees <addr>`** : Daftar fungsi yang dipanggil.
* **`ghidraanalyze vars <addr>`** : Inspeksi variabel lokal, tipe data, dan stack storage.
* **`ghidraanalyze rename <addr> <name>`** : Rename fungsi langsung di layar Ghidra.
* **`ghidraanalyze comment <addr> "<text>"`** : Tambah catatan/komentar di baris assembly.

---

### 2.  `assembly/exe/` — Windows PE Binary Doctor & Fixer
* **`exedoctor <file.exe>`** : Analisis kerusakan header PE, sections, dan memory-dump issues.
* **`exefix <file.exe> -o fixed.exe`** : Realign memory dump (WinDbg/Memdump) agar tidak error di Ghidra.
* **`exefix <file> --carve --strip-overlay`** : Bersihkan sampah shellcode prefix & trailing overlay.
* **`ghidraguide <file.exe>`** : Generate peta navigasi Ghidra & blueprint Writeup otomatis.

---

### 3.  `assembly/elf/` — Linux ELF Header Doctor & Inspector
* **`elfdoctor <file_elf>`** : Analisis header `\x7fELF`, arsitektur (x64/x86/ARM/MIPS), status stripped symbol, dan UPX packing.

---

### 4.  `assembly/binary/` — Multi-Arch Shellcode Disassembler
* **`disasm <payload.bin>`** : Disassemble shellcode x64/x86/ARM/ARM64.
* **Deteksi Pola Serangan** : PEB Walking (`gs:[0x60]` / `fs:[0x30]`), NOP Sleds (`\x90`), ROR13 API Hashing, dan Metasploit Stagers.
* **String & IP Extractor** : Auto-ekstraksi domain, IP, dan endpoint C2 di dalam biner mentah.

---

##  Quick Start Examples

```bash
# Buka program di Ghidra, jalankan GhidraAIBridge.java, lalu dari terminal:
ghidraanalyze status
ghidraanalyze goto 0x14000115a
ghidraanalyze callers 0x140001090
ghidraanalyze rename 0x140001090 rc4_shellcode_launcher

# Perbaiki memory dump Windows PE:
exefix DbgInfo_dumped.exe -o ./DbgInfo_fixed.exe

# Disassemble raw shellcode:
disasm shellcode.bin -a x64
```
