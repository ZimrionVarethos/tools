# AD1 Forensics Suite Documentation

Suite alat forensik digital **AccessData Logical Image (`.ad1`)** berbasis **Pure Python** berkinerja tinggi. Mampu membaca container gambar AD1 (termasuk multi-segmen `.ad1`, `.ad2`, `.ad3`, dst.) serta melakukan dekompresi zlib langsung dari memori tanpa membutuhkan aplikasi eksternal (seperti FTK Imager atau driver FUSE).

---

##  Daftar Isi
1. [Daftar Tools & Kegunaan](#1-daftar-tools--kegunaan)
2. [Opsi Ekspor File Laporan (MD, JSON, CSV, HTML)](#2-opsi-ekspor-file-laporan)
3. [Syntax & Contoh Menjalankan Tools](#3-syntax--contoh-menjalankan-tools)
   - [ad1history (Browser Forensics)](#a-ad1history--browser-forensics)
   - [ad1amcache (Program Execution Forensics)](#b-ad1amcache--program-execution-forensics)
   - [ad1NTUSER (User Behavioral Forensics)](#c-ad1ntuser--user-behavioral-forensics)
   - [ad1recent (Recent Items & LNK Forensics)](#d-ad1recent--recent-items--lnk-forensics)
   - [ad1extensions (Browser Extensions & Orphan LevelDB Triage)](#e-ad1extensions--browser-extensions--orphan-leveldb-triage)
   - [ad1scan (User Directory Tree & Sensitive Flag Finder)](#f-ad1scan--user-directory-tree--sensitive-flag-finder)
   - [ad1scandetail (User Personal Documents, Photos, & Notes Finder)](#g-ad1scandetail--user-personal-documents-photos--notes-finder)
   - [ad1cli (Info, Tree, & Extraction)](#h-ad1cli--info-tree--extraction)
4. [Cara Menjalankan di WSL Ubuntu & Windows](#4-cara-menjalankan-di-wsl-ubuntu--windows)

---

## 1. Daftar Tools & Kegunaan

| Nama Tool | Target Artefak | Deskripsi & Informasi yang Diekstrak |
| :--- | :--- | :--- |
| **`ad1history`** | `History`, `places.sqlite`, `History.db` | Ekstraksi seluruh riwayat browsing (Chrome, Edge, Firefox, Brave, Opera, Safari), URL lengkap, judul halaman, waktu kunjungan UTC/lokal, visit/typed count, profil pengguna, dan kata kunci pencarian (Google, Bing, YouTube). |
| **`ad1amcache`** | `Amcache.hve` (`Windows/appcompat/Programs/Amcache.hve`) | Ekstraksi artefak eksekusi biner Windows, hash SHA1, ukuran biner, vendor publisher, tanggal kompilasi PE, waktu eksekusi, serta deteksi eksekusi mencurigakan (`Temp`, `AppData`, `Downloads`). |
| **`ad1NTUSER`** | `NTUSER.DAT` (`Users/*/NTUSER.DAT`) | Analisis aktivitas user registry: **UserAssist** (eksekusi program GUI ROT13, Run Count, Focus Time), **TypedPaths** (history address bar Explorer), **RunMRU** (command dialog Win+R), **WordWheelQuery** (search bar Explorer), dan **RecentDocs**. |
| **`ad1recent`** | `.lnk` shortcuts & JumpLists (`Users/*/AppData/Roaming/Microsoft/Windows/Recent/*`) | Analisis shortcut `.lnk` dan JumpLists, path target file/dokumen, ukuran asli, MAC timestamps (Created/Accessed/Modified), dan resolusi AppID JumpList (Notepad, Word, Explorer, Chrome, VLC). |
| **`ad1extensions`** | `Preferences`, `Extensions/`, `Local Extension Settings/` (LevelDB) | Triage pintar ekstensi browser & deteksi ekstensi terhapus (*Orphan/Purged*). Menggunakan parser pure-Python LevelDB untuk mengekstrak string C2 (Discord Webhooks, Telegram API) & session cookies (`c_user`, `xs`, `sessionid`, `datr`, `auth_token`). Dilengkapi whitelist built-in resmi Google/Brave/Edge untuk mencegah *false positives*. |
| **`ad1scan`** | Direktori User (`Users/*/`, `home/*/`) | Scan visual pohon direktori profil user (*interactive folder tree*), otomatis men-highlight file sensitif (passwords, secrets, keys, credentials, token, `.env`, `.kdbx`), ekstraksi **CTF Flags** (`flag{...}`), deteksi dan decoding otomatis **Base64 strings** pada nama file & konten file, serta *Private Keys* / API tokens. |
| **`ad1scandetail`** | Personal User Folders (`Desktop`, `Documents`, `Pictures`, `Downloads`, `Music`, `Videos`, `Notes`) | **Zero-Noise User Content Hunter**: Khusus mencari dokumen, catatan (*notes*), foto/gambar, rekaman audio, dan download milik user tertentu (misal: `-u SERV`, `-u bagas`). **Secara ketat mengecualikan folder `AppData`**, cache, dan sampah OS untuk memudahkan penemuan artefak file asli user. Dilengkapi kategorisasi tipe file dan auto-preview flag. |
| **`ad1cli`** | Container AD1 | Utilitas inspeksi gambar container AD1: metadata & segmen (`info`), pohon hirarki folder (`tree`), dan ekstraksi file/folder (`extract`). |

---

## 2. Opsi Ekspor File Laporan

Seluruh tools forensik di atas mendukung ekspor kustom ke berbagai format laporan:

| Flag Argumen | Format | Keunggulan & Karakteristik |
| :--- | :---: | :--- |
| **`--md <file.md>`** / **`--markdown <file.md>`** | **Markdown** | **Sangat ringan**, bersih, mudah dibaca langsung di terminal/GitHub/editor teks, cocok untuk dokumentasi laporan cepat. |
| **`--json <file.json>`** | **JSON** | **Sangat ringan & terstruktur**, ramah integrasi automasi script, parsing Python/jq, SIEM, atau API pipeline. |
| **`--csv <file.csv>`** | **CSV** | Format tabular spreadsheet standar, siap dibuka di Excel / LibreOffice Calc. |
| **`--html <file.html>`** | **HTML** | Laporan web interaktif mandiri (*standalone*), dilengkapi kotak pencarian live, filter, pagination, dan dark mode. |
| **`--export-all`** | **Semua** | Menghasilkan file **`.md`**, **`.json`**, **`.csv`**, dan **`.html`** sekaligus secara otomatis menggunakan nama dasar image. |

---

## 3. Syntax & Contoh Menjalankan Tools

### A. `ad1history` – Browser Forensics

#### Syntax Lengkap:
```bash
ad1history <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-b`, `--browser [all|chrome|edge|firefox|brave|opera|safari]` : Filter browser tertentu (default: all).
- `-q`, `--query "<keyword>"` : Filter URL, judul halaman, atau domain berdasarkan kata kunci.
- `--search-only` : Hanya tampilkan URL yang merupakan kueri pencarian web (Google, Bing, DuckDuckGo, YouTube).
- `-l`, `--limit <jumlah>` : Batas jumlah baris yang ditampilkan di tabel terminal (default: 100).
- `--creds-dir <folder>` : Lokasi folder tujuan ekstraksi paket bundle DPAPI (default: `./extracted_credentials`).
- `--no-creds-extract` : Nonaktifkan auto-ekstraksi bundle kredensial DPAPI saat login URL terdeteksi.
- `--md <output.md>` : Ekspor laporan ke file Markdown.
- `--json <output.json>` : Ekspor laporan ke file JSON.
- `--csv <output.csv>` : Ekspor laporan ke file CSV.
- `--html <output.html>` : Ekspor laporan ke file HTML interaktif.
- `--export-all` : Ekspor ke MD, JSON, CSV, dan HTML sekaligus.

>  **Fitur Spesial: Korelasi Pintar Login URL & Auto-Extract DPAPI Bundle**
> - **Trigger Pintar**: Ketika menemukan URL aktivitas autentikasi/login (`login`, `signin`, `auth`, `oauth`, `session`, `portal`, `sso`, dll.), tool otomatis memeriksa apakah ada database `Login Data` di profil browser tersebut.
> - **Auto-Extract DPAPI Bundle**: Jika `Login Data` ada, tool langsung mengekstrak paket artefak lengkap untuk dekripsi offline (**`Login Data`**, **`Local State`** `os_crypt`, **`Protect/<SID>/...`** DPAPI MasterKeys, **`SAM`**, **`SYSTEM`**, dan **`NTUSER.DAT`**).
> - **Anti-Noise**: Jika tidak ada aktivitas login atau tidak ada database `Login Data` (noise/umpan kosong), tool **TIDAK** akan mengekstrak file sistem agar tidak mengotori workspace Anda.

#### Contoh Penggunaan:
```bash
# 1. Analisis riwayat browsing (Otomatis deteksi login URL & ekstrak bundle DPAPI jika ada Login Data)
ad1history evidence.ad1

# 2. Analisis & langsung dekripsi password plain menggunakan password user
ad1history evidence.ad1 -p "Password123"

# 3. Analisis & langsung bruteforce DPAPI MasterKey menggunakan rockyou wordlist
ad1history evidence.ad1 -w /usr/share/wordlists/rockyou.txt --md hasil_history_decrypted.md

# 4. Ekspor ke file Markdown (.md) dan JSON (.json) yang ringan (termasuk rincian akun DPAPI)
ad1history evidence.ad1 --md hasil_history.md --json hasil_history.json

# 5. Tentukan folder tujuan ekstraksi paket DPAPI kustom
ad1history evidence.ad1 --creds-dir ./hasil_dpapi_investigasi

# 6. Filter hanya browser Google Chrome dan batasi 50 hasil
ad1history evidence.ad1 --browser chrome --limit 50

# 7. Cari URL yang mengandung kata "github" atau "login"
ad1history evidence.ad1 -q "login"

# 8. Ekspor seluruh format sekaligus
ad1history evidence.ad1 --export-all
```

---

### B. `ad1dpapi` – Automated DPAPI MasterKey Recovery & Password Decryptor

Tool khusus untuk membuka proteksi DPAPI MasterKey Windows dan mendekripsi seluruh password yang tersimpan di Chromium `Login Data` secara offline.

#### Syntax Lengkap:
```bash
ad1dpapi <evidence.ad1|folder_bundle> [opsi]
```

#### Opsi yang Tersedia:
- `-p`, `--password "<plain_pwd>"` : Dekripsi langsung menggunakan password Windows plaintext milik user.
- `--ntlm "<hash_hex>"` : Dekripsi langsung menggunakan NTLM hash user (32-karakter hex).
- `-w`, `--wordlist <rockyou.txt>` : Jalankan fast bruteforce terhadap HMAC checksum MasterKey file.
- `--auto-sam` : Ekstrak NTLM hash secara otomatis dari hive SAM & SYSTEM untuk zero-touch auto-decryption.
- `--md <output.md>` : Ekspor tabel password plaintext ke Markdown.
- `--json <output.json>` : Ekspor ke file JSON.
- `--csv <output.csv>` : Ekspor ke file CSV.
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Dekripsi menggunakan password user langsung
ad1dpapi evidence.ad1 -p "Password123"

# 2. Dekripsi menggunakan hash NTLM
ad1dpapi evidence.ad1 --ntlm "e0fb1f2654f21e6747d4e67fbe607293"

# 3. Bruteforce MasterKey menggunakan Rockyou / wordlist
ad1dpapi evidence.ad1 -w /usr/share/wordlists/rockyou.txt --md decrypted_passwords.md

# 4. Jalankan pada folder kredensial yang sudah diekstrak sebelumnya
ad1dpapi ./extracted_credentials/Alice_Google_Chrome -p "Password123"

# 5. Setup / unduh rockyou.txt di WSL Ubuntu jika belum ada:
bash /mnt/d/tools/wordlists/setup_rockyou.sh
```

---

### C. `ad1amcache` – Program Execution Forensics

#### Syntax Lengkap:
```bash
ad1amcache <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-q`, `--query "<keyword>"` : Filter berdasarkan nama program, path biner, SHA1 hash, atau publisher.
- `-l`, `--limit <jumlah>` : Batas baris di tabel terminal (default: 100).
- `--md <output.md>` : Ekspor ke Markdown (.md).
- `--json <output.json>` : Ekspor ke JSON (.json).
- `--csv <output.csv>` : Ekspor ke CSV (.csv).
- `--html <output.html>` : Ekspor ke HTML (.html).
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Analisis seluruh eksekusi program Amcache
ad1amcache evidence.ad1

# 2. Ekspor ke file Markdown dan JSON
ad1amcache evidence.ad1 --md laporan_amcache.md --json amcache.json

# 3. Cari eksekusi program tertentu (misal: mimikatz, powershell, cmd)
ad1amcache evidence.ad1 -q "powershell" --md powershell_exec.md
ad1amcache evidence.ad1 -q "mimikatz"

# 4. Ekspor semua format
ad1amcache evidence.ad1 --export-all
```

---

### C. `ad1NTUSER` – User Behavioral Forensics

#### Syntax Lengkap:
```bash
ad1NTUSER <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-q`, `--query "<keyword>"` : Filter berdasarkan user account, kategori artefak, program, command Win+R, atau path.
- `-l`, `--limit <jumlah>` : Batas baris di terminal (default: 100).
- `--md <output.md>` : Ekspor ke Markdown (.md).
- `--json <output.json>` : Ekspor ke JSON (.json).
- `--csv <output.csv>` : Ekspor ke CSV (.csv).
- `--html <output.html>` : Ekspor ke HTML (.html).
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Analisis seluruh aktivitas user registry
ad1NTUSER evidence.ad1

# 2. Ekspor ke Markdown dan JSON
ad1NTUSER evidence.ad1 --md laporan_user.md --json user_activity.json

# 3. Cari aktivitas user tertentu atau perintah Win+R tertentu
ad1NTUSER evidence.ad1 -q "Alice" --md aktivitas_alice.md
ad1NTUSER evidence.ad1 -q "powershell"

# 4. Ekspor semua format
ad1NTUSER evidence.ad1 --export-all
```

---

### D. `ad1recent` – Recent Items & LNK Forensics

#### Syntax Lengkap:
```bash
ad1recent <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-q`, `--query "<keyword>"` : Filter berdasarkan target path, nama dokumen, atau user account.
- `-l`, `--limit <jumlah>` : Batas baris di terminal (default: 100).
- `--md <output.md>` : Ekspor ke Markdown (.md).
- `--json <output.json>` : Ekspor ke JSON (.json).
- `--csv <output.csv>` : Ekspor ke CSV (.csv).
- `--html <output.html>` : Ekspor ke HTML (.html).
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Analisis file yang baru saja diakses user
ad1recent evidence.ad1

# 2. Ekspor ke Markdown dan JSON
ad1recent evidence.ad1 --md file_recent.md --json recent.json

# 3. Cari dokumen dengan ekstensi tertentu (misal: pdf, docx, xlsx, exe)
ad1recent evidence.ad1 -q "pdf" --md dokumen_pdf_terbuka.md
ad1recent evidence.ad1 -q "passwords"

# 4. Ekspor semua format
ad1recent evidence.ad1 --export-all
```

---

### E. `ad1extensions` – Browser Extensions & Orphan LevelDB Triage

#### Syntax Lengkap:
```bash
ad1extensions <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-q`, `--query "<keyword>"` : Filter berdasarkan nama ekstensi, ID, user, permission, atau string IoC/C2.
- `-a`, `--all` : Tampilkan seluruh ekstensi termasuk komponen built-in resmi browser (default: menyembunyikan built-in agar terminal bersih).
- `-l`, `--limit <jumlah>` : Batas baris di terminal (default: 100).
- `--md <output.md>` : Ekspor laporan ke Markdown (.md).
- `--json <output.json>` : Ekspor laporan ke JSON (.json).
- `--csv <output.csv>` : Ekspor laporan ke CSV (.csv).
- `--html <output.html>` : Ekspor laporan ke HTML (.html).
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Triage pintar ekstensi pihak ketiga & sisa storage LevelDB (Orphan / Purged)
ad1extensions evidence.ad1

# 2. Ekspor ke file Markdown dan JSON yang ringan
ad1extensions evidence.ad1 --md laporan_ekstensi.md --json ekstensi.json

# 3. Tampilkan semua ekstensi termasuk built-in browser
ad1extensions evidence.ad1 --all

# 4. Cari ekstensi mencurigakan atau indikator C2 tertentu (misal: discord, token, cookies)
ad1extensions evidence.ad1 -q "discord" --md temuan_webhook.md
ad1extensions evidence.ad1 -q "cookies"

# 5. Ekspor semua format sekaligus
ad1extensions evidence.ad1 --export-all
```

---

### F. `ad1scan` – User Directory Tree & Sensitive Flag Finder

#### Syntax Lengkap:
```bash
ad1scan <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-u`, `--user <nama>` : Filter scan ke profil user tertentu (misal: `Alice`).
- `-d`, `--depth <angka>` : Batas kedalaman visual folder tree (default: 5).
- `-q`, `--query "<keyword>"` : Filter file berdasarkan kata kunci pada path atau nama file.
- `--sensitive-only` / `--flags-only` : Hanya tampilkan tabel temuan file sensitif & flag CTF tanpa visual tree.
- `--tree-only` : Hanya tampilkan visual folder tree tanpa tabel rincian file.
- `--full` : Scan seluruh partisi/direktori container AD1 (bukan hanya folder user).
- `--no-content` : Lewati inspeksi pembacaan isi konten file (hanya scan nama file).
- `-l`, `--limit <jumlah>` : Batas baris tabel terminal (default: 100).
- `--md <output.md>` : Ekspor laporan ke Markdown (.md).
- `--json <output.json>` : Ekspor laporan ke JSON (.json).
- `--csv <output.csv>` : Ekspor laporan ke CSV (.csv).
- `--html <output.html>` : Ekspor laporan ke HTML (.html).
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Scan profil user, render visual tree, dan highlight file sensitif / flag
ad1scan evidence.ad1

# 2. Hanya tampilkan tabel temuan sensitif (Flags, Keys, Base64, Passwords)
ad1scan evidence.ad1 --sensitive-only

# 3. Ekspor laporan scan ke file Markdown dan JSON
ad1scan evidence.ad1 --md hasil_scan.md --json scan.json

# 4. Filter scan khusus profil user Alice dengan kedalaman tree 4
ad1scan evidence.ad1 --user Alice -d 4

# 5. Cari file sensitif tertentu (misal: .kdbx, id_rsa, flag, .env)
ad1scan evidence.ad1 -q "id_rsa"
ad1scan evidence.ad1 -q "flag"

# 6. Ekspor seluruh format sekaligus
ad1scan evidence.ad1 --export-all
```

---

### G. `ad1scandetail` – User Personal Documents, Photos, & Notes Finder

#### Syntax Lengkap:
```bash
ad1scandetail <evidence.ad1> [opsi]
```

#### Opsi yang Tersedia:
- `-u`, `--user <nama>` : Target spesifik ke username tertentu (misal: `-u SERV`, `-u bagas`, `-u Alice`).
- `-c`, `--category <kategori>` : Filter kategori file (`Documents`, `Images`, `Audio`, `Archives`, `Scripts`).
- `-l`, `--limit <jumlah>` : Batas baris tabel terminal (default: 100).
- `--no-content` : Lewati auto-preview isi file & flag.
- `--md <output.md>` : Ekspor laporan ke Markdown (.md).
- `--json <output.json>` : Ekspor laporan ke JSON (.json).
- `--csv <output.csv>` : Ekspor laporan ke CSV (.csv).
- `--html <output.html>` : Ekspor laporan ke HTML (.html).
- `--export-all` : Ekspor ke semua format otomatis.

#### Contoh Penggunaan:
```bash
# 1. Cari seluruh dokumen, foto, notes, dan file personal (Otomatis skip AppData noise)
ad1scandetail evidence.ad1

# 2. Cari file personal khusus milik user SERV atau bagas
ad1scandetail evidence.ad1 -u SERV
ad1scandetail evidence.ad1 -u bagas

# 3. Filter hanya dokumen / notes teks
ad1scandetail evidence.ad1 -c "Documents"

# 4. Filter hanya gambar / foto
ad1scandetail evidence.ad1 -c "Images"

# 5. Ekspor temuan dokumen ke file Markdown dan JSON
ad1scandetail evidence.ad1 -u SERV --md serv_dokumen.md --json serv_dokumen.json

# 6. Ekspor semua format sekaligus (MD, JSON, CSV, HTML)
ad1scandetail evidence.ad1 --export-all
```

---

### H. `ad1cli` – Info, Tree, & Extraction

#### 1. Melihat Metadata & Informasi Image (`info`)
```bash
ad1cli info -i evidence.ad1
```

#### 2. Melihat Struktur Pohon Direktori (`tree`)
```bash
# Tree kedalaman standar (5 tingkat)
ad1cli tree -i evidence.ad1

# Tree kedalaman kustom (misal: 8 tingkat)
ad1cli tree -i evidence.ad1 -d 8
```

#### 3. Ekstraksi File dari Container AD1 (`extract`)
```bash
# Ekstrak seluruh file ke direktori tujuan
ad1cli extract -i evidence.ad1 -o ./hasil_ekstrak

# Ekstrak hanya file yang cocok dengan pola/wildcard
ad1cli extract -i evidence.ad1 -o ./sqlite_files -p "*.sqlite"
ad1cli extract -i evidence.ad1 -o ./registry_files -p "*.hve"
```

---

## 4. Cara Menjalankan di WSL Ubuntu & Windows

### A. Melalui Global Aliases di WSL Ubuntu (Rekomendasi)
Karena alias sudah terdaftar di `~/.bashrc`, Anda bisa menjalankan langsung dari folder mana saja:
```bash
ad1history /path/to/evidence.ad1 --md history.md
ad1amcache /path/to/evidence.ad1 --md amcache.md
ad1NTUSER /path/to/evidence.ad1 --md ntuser.md
ad1recent /path/to/evidence.ad1 --md recent.md
ad1extensions /path/to/evidence.ad1 --md extensions.md
ad1scan /path/to/evidence.ad1 --md scan.md
ad1scandetail /path/to/evidence.ad1 --md personal_files.md
```

### B. Melalui Master Runner `tools`
```bash
# Di WSL / Linux:
tools ad1 history evidence.ad1 --md report.md
tools ad1 amcache evidence.ad1 --json report.json
tools ad1 ntuser evidence.ad1 --export-all
tools ad1 recent evidence.ad1
tools ad1 extensions evidence.ad1 --export-all
tools ad1 scan evidence.ad1 --sensitive-only
tools ad1 info -i evidence.ad1
tools ad1 tree -i evidence.ad1 -d 5

# Di Windows (CMD / PowerShell):
.\tools.bat ad1 history evidence.ad1 --md report.md
.\tools.bat ad1 scan evidence.ad1 --export-all
```

### C. Eksekusi Langsung Script Python
```bash
python3 ad1/history.py evidence.ad1 --md history.md --json history.json
python3 ad1/amcache.py evidence.ad1 --md amcache.md
python3 ad1/ntuser.py evidence.ad1 --md ntuser.md
python3 ad1/recent.py evidence.ad1 --md recent.md
python3 ad1/extensions.py evidence.ad1 --md extensions.md
python3 ad1/scan.py evidence.ad1 --md scan.md
```
