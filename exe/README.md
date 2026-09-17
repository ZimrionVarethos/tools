# Universal Windows PE Binary Doctor & Fixer (`exefix` / `exe/`)

Suite alat diagnostik, inspeksi integritas, dan perbaikan biner executable Windows (**`.exe`**, **`.dll`**, **`.sys`**) berbasis **Pure Python**. Dirancang khusus untuk memperbaiki artefak biner hasil *dumping* memori (seperti dari **WinDbg `.writemem`**, **Volatility `procdump`**, crash dumps) atau biner CTF yang rusak/terkorupsi agar dapat dibongkar dan didekompilasi dengan bersih tanpa error di **Ghidra**, **IDA Pro**, dan **x64dbg**.

---

##  Daftar Isi
1. [Fitur Utama & Modul Diagnostik](#1-fitur-utama--modul-diagnostik)
2. [Kenapa Hasil Dump Memori Perlu Diperbaiki?](#2-kenapa-hasil-dump-memori-perlu-diperbaiki)
3. [Syntax & Contoh Menjalankan Tools](#3-syntax--contoh-menjalankan-tools)
   - [exefix --diagnose (Inspeksi Kerusakan PE)](#a-exefix---diagnose-inspeksi-kerusakan-pe)
   - [exefix (Realign Memory Dump untuk Ghidra/IDA)](#b-exefix-realign-memory-dump-untuk-ghidraida)
   - [exefix --unmap (Unpack ke Format Disk Asli)](#c-exefix---unmap-unpack-ke-format-disk-asli)
   - [exefix --carve & --strip-overlay (Bersihkan Sampah / Polyglot)](#d-exefix---carve----strip-overlay-bersihkan-sampah--polyglot)
4. [Cara Menjalankan di WSL Ubuntu & Windows](#4-cara-menjalankan-di-wsl-ubuntu--windows)

---

## 1. Fitur Utama & Modul Diagnostik

| Fitur / Sub-Modul | Deskripsi Masalah yang Diperbaiki |
| :--- | :--- |
| ** Deep PE Health Diagnoser** | Memeriksa seluruh header PE (DOS Header `MZ`, `e_lfanew`, PE Signature `PE\0\0`, COFF Header, OptionalHeader PE32/PE32+) serta memetakan matriks seluruh section dan data directory. Memberikan alert detail jika ada pointer yang rusak/out-of-bounds. |
| ** Memory Dump Realigner (Default)** | Memperbaiki biner hasil dump memori (WinDbg/Memdump) dengan menyamakan `PointerToRawData = VirtualAddress` dan `FileAlignment = SectionAlignment`. Menghilangkan error *NullPointerException* / dekompilasi nyeleneh di Ghidra. |
| ** True Memory-to-Disk Unmapper** | Membongkar (*unmap*) biner dari layout memori dan menyusunnya kembali ke format file disk asli dengan alignment 512-byte (`0x200`), merekonstruksi file mentah seperti sebelum dieksekusi di RAM. |
| ** Embedded PE Carver (`--carve`)** | Otomatis mendeteksi jika file PE terbungkus di dalam file sampah / polyglot / shellcode prefix, lalu mengekstrak biner asli mulai dari signature `MZ`. |
| ** Overlay / Junk Stripper (`--strip-overlay`)** | Memotong dan membersihkan byte sampah non-PE yang tertempel di bagian akhir file (*trailing overlay*). |
| ** ImageBase Sync (`--base-addr`)** | Memperbarui nilai `ImageBase` di header PE sesuai alamat ASLR memori aktual tempat proses berjalan. |

---

## 2. Kenapa Hasil Dump Memori Perlu Diperbaiki?

Ketika suatu file `.exe` dijalankan di Windows, OS memetakan (*mapping*) section-section biner ke alamat virtual yang berbeda dari letaknya di harddisk:
* Di harddisk: Section `.text` ada di offset `0x400`, `.rdata` di `0x85000`.
* Di RAM: Section `.text` dipindahkan ke `0x1000`, `.rdata` ke `0x88000`.

Jika kita mendump biner langsung dari memori (misal via WinDbg `.writemem`), **header biner masih mengira data ada di offset disk**. Akibatnya ketika dibuka di Ghidra:
* Ghidra membaca Import Table (`.idata`) dan string konstanta (`.rdata`) di alamat yang salah $\rightarrow$ Decompiler menjadi kacau, banyak fungsi berlabel `<UNRESOLVED_CALL_0x...>`, dan string bergeser.
* **`exefix`** secara otomatis menyinkronkan seluruh pointer section dan header sehingga Ghidra dapat membaca seluruh fungsi dan variabel dengan 100% presisi.

---

## 3. Syntax & Contoh Menjalankan Tools

### A. `exefix --diagnose` (Inspeksi Kerusakan PE)

Menganalisis file binary untuk mencari tahu kenapa biner tidak bisa dibuka atau corrupt:

```bash
exefix DbgInfo.exe --diagnose
```
* **Output yang ditampilkan:**
  * Ringkasan Header, Arsitektur (x64/x86), ImageBase, dan Alignments.
  * Deteksi apakah file berformat Memory-Mapped Dump atau Disk Image.
  * Tabel Health Issues (Critical, Warning, Info).
  * Matriks Section Headers lengkap.

---

### B. `exefix` (Realign Memory Dump untuk Ghidra/IDA)

Memperbaiki hasil dump WinDbg/Minidump agar decompiler Ghidra dan IDA Pro berjalan mulus:

```bash
# Perbaiki biner dan simpan ke file baru:
exefix DbgInfo_dumped.exe -o ./DbgInfo_fixed.exe

# Atau perbaiki sambil menyinkronkan ImageBase ASLR aktual:
exefix DbgInfo_dumped.exe --base-addr 0x7ff62fbd0000 -o ./DbgInfo_fixed.exe
```

---

### C. `exefix --unmap` (Unpack ke Format Disk Asli)

Mengonversi struktur memori kembali ke bentuk file disk asli (FileAlignment 512-byte / 0x200):

```bash
exefix DbgInfo_dumped.exe --unmap -o ./DbgInfo_disk.exe
```

---

### D. `exefix --carve & --strip-overlay` (Bersihkan Sampah / Polyglot)

Membersihkan file malware/CTF yang disisipkan sampah di depan (`MZ` bergeser) atau sampah di belakang (*overlay*):

```bash
# Carve PE yang diawali sampah shellcode & bersihkan overlay di belakang:
exefix suspicious_payload.bin --carve --strip-overlay -o ./clean_binary.exe
```

---

## 4. Cara Menjalankan di WSL Ubuntu & Windows

### Via Alias Global di WSL
```bash
# Setup alias sekali di awal:
bash /mnt/d/tools/install_alias.sh
source ~/.bashrc

# Jalankan perintah:
exefix DbgInfo_dumped.exe -o DbgInfo_fixed.exe
exedoctor DbgInfo.exe --diagnose
```

### Via Master Dispatcher (`tools.py`)
```bash
python3 tools.py exe fix DbgInfo_dumped.exe -o DbgInfo_fixed.exe
python3 tools.py exe diagnose DbgInfo.exe
```

### Via Windows PowerShell / CMD
```powershell
python D:\tools\exe\fixer.py D:\extracted_malware\DbgInfo.exe -o D:\extracted_malware\DbgInfo_fixed.exe
```

---

## 5.  Ghidra On-Demand AI Companion Bridge (`ghidracli` / `ghidrabridge`)

Sistem interaksi 2 arah antara Ghidra GUI di Windows dengan terminal analis **100% On-Demand (Hanya berjalan ketika diperintah manual)**.

### A. Cara Menyalakan Server di Ghidra GUI (Hanya Saat Mau Belajar)
1. Buka Ghidra di Windows.
2. Klik menu atas: **`Window`** $\rightarrow$ **`Script Manager`**.
3. Di kotak filter, ketik: **`GhidraAIBridge.java`**.
4. Klik tombol **Run (Ikon Play Hijau)**.
5. Server lokal aktif di `http://127.0.0.1:13370` *(Bisa dimatikan kapan saja dengan tombol Stop Merah)*.

### B. Perintah Interaktif via Terminal (`ghidracli`)
```bash
# 1. Cek koneksi ke Ghidra:
ghidracli status

# 2. Decompile & bedah fungsi tempat kursor lo berada di Ghidra:
ghidracli current

# 3. Decompile fungsi di alamat spesifik:
ghidracli decompile 0x14000115a

# 4. Cari semua referensi (XREFs) ke suatu alamat:
ghidracli xref 0x1400014b0

# 5. Rename nama fungsi jelek di layar Ghidra lo secara manual:
ghidracli rename 0x140001100 rc4_decrypt_payload

# 6. Tambahkan komentar penjelasan di baris assembly:
ghidracli comment 0x14000115a "RC4 Decryption Key: xobvrE_x11mb"
```
