#  Ghidra Interactive On-Demand AI Companion (`assembly/ghidra/`)

Modul jembatan interaktif 2 arah antara **Ghidra GUI di Windows** dengan terminal analis berbasis **Zero Automation (100% Berjalan Hanya Berdasarkan Perintah Manual)**.

---

##  Fitur Utama `ghidraanalyze`

| Perintah | Deskripsi & Kegunaan |
| :--- | :--- |
| **`ghidraanalyze status`** | Memeriksa apakah Ghidra bridge aktif, nama program yang sedang dibuka, Image Base, dan rentang alamat memori. |
| **`ghidraanalyze goto <addr>`** | **Menggeser kursor dan layar Ghidra GUI lo langsung ke alamat tujuan!** (Tanpa perlu tekan `G` manual di Ghidra). |
| **`ghidraanalyze current`** | Mendekompresi dan membedah fungsi tempat kursor lo berada di Ghidra saat ini dengan *syntax highlighting* C. |
| **`ghidraanalyze decompile <addr>`** | Mendekompresi fungsi di alamat tertentu dan menampilkan kode Pseudo-C bersih. |
| **`ghidraanalyze search <query>`** | Mencari teks string, simbol fungsi, atau Windows API import di seluruh program. |
| **`ghidraanalyze callers <addr>`** | Menampilkan pohon pemanggilan (*Call Tree*): fungsi apa saja yang memanggil fungsi target. |
| **`ghidraanalyze callees <addr>`** | Menampilkan fungsi apa saja yang dipanggil oleh fungsi target (termasuk API eksternal). |
| **`ghidraanalyze vars <addr>`** | Membedah daftar variabel lokal, parameter, tipe data, dan layout stack memori. |
| **`ghidraanalyze xref <addr>`** | Menampilkan semua *Cross-References* (siapa yang membaca, menulis, atau memanggil alamat ini). |
| **`ghidraanalyze rename <addr> <name>`** | Mengubah nama fungsi jelek (misal `FUN_140001090`) langsung di layar Ghidra lo! |
| **`ghidraanalyze comment <addr> "<text>"`** | Menambahkan catatan (*plate comment*) di atas baris assembly Ghidra lo. |
| **`ghidraanalyze strings`** | Menampilkan daftar seluruh string yang terdefinisi di dalam program. |

---

##  Cara Menyalakan & Menggunakan

### 1. Di Ghidra GUI (Windows):
1. Buka Ghidra dan load binary executable lo.
2. Klik menu atas: **`Window`** $\rightarrow$ **`Script Manager`**.
3. Di kotak filter, ketik: **`GhidraAIBridge.java`**.
4. Klik tombol **Run (Ikon Play Hijau)**.
5. Server aktif di background *(tanpa ada popup naga yang mengganggu)*.
   *(Untuk mematikan kapan saja, cukup klik Run lagi pada script tersebut untuk toggle off).*

### 2. Di Terminal Analis (WSL / Linux / Windows):
```bash
# Cek koneksi:
ghidraanalyze status

# Geser layar Ghidra ke fungsi decryptor:
ghidraanalyze goto 0x14000115a

# Bedah fungsi di posisi kursor:
ghidraanalyze current

# Cari letak Windows API VirtualProtect:
ghidraanalyze search VirtualProtect --type api

# Lihat Call Tree fungsi main:
ghidraanalyze callers 0x140001090

# Rename fungsi jadi rapi di layar Ghidra:
ghidraanalyze rename 0x140001090 rc4_shellcode_launcher
```
