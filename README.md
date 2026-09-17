# 🔬 Unified DFIR Forensic Toolkit

Platform Forensik Digital & Incident Response modular dan universal berbasis **Pure Python & Rust** untuk analisis citra logikal AccessData (**`.ad1`**), *Packet Captures* (**`.pcap`**, **`.pcapng`**), *Windows Memory/Crash Dumps* (**`.dmp`**, **`.raw`**), *Linux LiME RAM Dumps* (**`.lime`**, **`.mem`**, **`.raw`**), *Disk Images* (**`.img`**, **`.e01`**), serta file biner investigasi lainnya.

---

## 🧭 Modul Forensik & Dokumentasi Terkait

Toolkit ini diorganisasi ke dalam 8 modul spesifik dengan dokumentasi lengkap di setiap foldernya:

| Modul | Target Artefak | Tools Utama | Link Dokumentasi |
| :--- | :--- | :--- | :--- |
| **Universal Core & Rust** | Semua Format File | `globalscan2`, `strings2`, `binwalk2`, `memcarve`, `volrust`, `globalscan` | [📄 `core/README.md`](core/README.md) |
| **PCAP Network Suite** | `.pcap`, `.pcapng`, `.cap` | `pcapendpoint`, `pcapfirst`, `pcaptree`, `pcapfile`, `pcapstream`, `pcapscan`, `pcapscanstream`, `pcappayload`, `pcapportpayload` | [📄 `pcap/README.md`](pcap/README.md) |
| **Windows Memory Suite** | `.dmp`, `.raw`, `.bin` | `dmpscan`, `dmpdump`, `dmppeb`, `dmpmodules`, `dmpflags`, `memcarve`, `volrust` | [📄 `dmp/README.md`](dmp/README.md) |
| **Linux LiME Memory Suite**| `.lime`, `.raw`, `.mem` | `limescan`, `limebuild`, `limefast` | [📄 `lime/README.md`](lime/README.md) |
| **Assembly & Reversing** | `.exe`, `.elf`, Shellcode | `ghidraanalyze`, `exefix`, `exedoctor`, `ghidraguide`, `elfdoctor`, `disasm` | [📄 `assembly/README.md`](assembly/README.md) |
| **Cryptography & Obfuscation** | Ciphertext, Hash, Keys | `ciphercheck`, `cryptohunt`, `T_aes`, `T_chacha20`, `T_xor`, `T_rc4`, `T_rsa`, `T_classical` | [📄 `cipher/README.md`](cipher/README.md) |
| **Steganography & Audio** | `.png`, `.jpg`, `.wav` | `stegoscan`, `stegodiff`, `stegocrack`, `stegoaudio` | [📄 `stego/README.md`](stego/README.md) |
| **AD1 Forensics Suite** | `.ad1`, multi-segment `.ad2` | `ad1history`, `ad1dpapi`, `ad1amcache`, `ad1ntuser`, `ad1recent`, `ad1extensions`, `ad1scan`, `ad1scandetail` | [📄 `ad1/README.md`](ad1/README.md) |

---

## 🌟 Ringkasan Fitur & Perintah per Modul

### 1. ⚡ Universal & Rust High-Performance Suite (`core/`, `bin/`)
Dapat dijalankan pada **SEMUA format file** tanpa terkecuali (`.dmp`, `.raw`, `.pcap`, `.ad1`, `.img`, `.bin`, dll.):
- **`globalscan2`** (Rust ⚡): Porting resmi **versi Rust** berkinerja tinggi. Memanfaatkan *zero-copy memory mapping* (`memmap2`) dan *parallel computing* (`rayon`), mengeksekusi perhitungan hash, entropy, strings, regex, dan brute-force XOR **puluhan hingga ratusan kali lebih cepat**.
- **`strings2`** (Rust ⚡): Universal Forensic Strings Carving & Search Engine ultra-cepat. Ekstraksi string ASCII & UTF-16LE, pencarian regex instant, context lines (`-C`), dan offset print (`-o`).
- **`binwalk2`** (Rust ⚡): Universal Firmware & Binary Signature Carver ultra-cepat berbasis zero-copy SIMD. Ekstraksi otomatis (`-e -o <dir>`).
- **`memcarve`** (Rust ⚡): Universal Raw Memory Carver & Heuristic Multi-Page Assembler. Memindai memori gigabyte dalam hitungan detik, auto-deteksi alokasi halaman LIFO *reverse order* vs *forward linear*, verifikasi checksum (Adler32, SHA-1, ELF headers).
- **`volrust`** (`vol-rs`): Porting Volatility 3 berbasis Rust berkinerja tinggi (20x s/d 500x lebih cepat tanpa bottleneck Python).
- **`globalscan`** (Python): Universal file scanner lama berbasis Python (tetap utuh dan aktif).

```bash
# Universal file scanner & flag hunter:
globalscan2 cute.DMP
globalscan2 memory.raw --flags-only -p "CTF{"

# Fast forensic strings search dengan context:
strings2 -s "api/v1" capture.pcap -C 2
strings2 -r "flag{[^}]+}" memory.raw

# Fast binary & firmware carving:
binwalk2 firmware.bin -e -o ./carved_output
```

---

### 2. 🌐 Modul PCAP Network Forensics (`pcap/`)
Analisis lalu lintas jaringan tingkat lanjut (`.pcap`, `.pcapng`):
- **`pcapendpoint`** (`pcapend`, `pcapurl`): **Automated Threat Triage, C2 Seed Carver & Fake Telemetry Hunter**.
  - Deteksi otomatis endpoint berbahaya: C2 beaconing, flag bocor, parameter seed/secret (`sid`, `seed`, `cmd`, `token`), payload eksfiltrasi.
  - **Fake Telemetry Masquerade Detector**: Membedakan domain telemetri resmi vendor vs impostor/spoofed domain (misal `ms-telemetry-sync.xyz`).
  - **Recursive Multi-Base Unpacker**: Otomatis decode Base64, Base32, Hex, URL-encoding di path URL, parameter query, dan body JSON.
  - **Shannon Entropy Scoring**: Deteksi URL dengan enkripsi atau Domain Generation Algorithm (DGA).
  - Follow percakapan stream dua arah langsung via opsi `-s <STREAM_ID>`.
- **`pcapfirst`**: Macro triage dashboard (metadata, protokol dominan, klasifikasi port, top talkers 5-tuple, auto-suggested next steps).
- **`pcaptree`**: Visualisasi *Protocol Hierarchy Tree*, matriks *Top Talkers Endpoints*, dan daftar seluruh percakapan *TCP/UDP Streams*.
- **`pcapfile`**: Rekonstruksi & *carving* file yang ditransfer lewat jaringan (CaRT, WASM, PE, ELF, ZIP, PDF, PNG, dll.) langsung ke folder (`-o / --export-dir`).
- **`pcapstream`**: *Wireshark-Style Follow Stream* bidirectional (Client Cyan, Server Hijau), mode *Hex Dump* 16-byte (`--hex`), dan pencarian teks (`--search`).
- **`pcapscan`**: Threat & flag hunter (C2 patterns, high-entropy ciphertext, multi-layer unpacker).
- **`pcapscanstream`**: Deep stream scanner dengan automated XOR brute-force (`0x01`..`0xFF`), unmasking WebSocket RFC 6455, dan entropy scoring.
- **`pcappayload`**: Ekstraksi payload per-paket (DNS tunneling subdomains, ICMP ping echo sequence, raw UDP/TCP).
- **`pcapportpayload`**: Covert channel decoder via manipulasi port (Port-to-ASCII), discrete reassembler, dan field `IP.ID` / `TTL`.

```bash
# Scan otomatis seluruh stream untuk C2, Flag, Seed & Exfil:
pcapendpoint wire.pcap

# Follow percakapan request-response stream #49:
pcapendpoint wire.pcap -s 49

# Tampilkan seluruh endpoint (termasuk background OS telemetry):
pcapendpoint wire.pcap --all

# Macro triage dashboard & protocol tree:
pcapfirst traffic.pcapng
pcaptree traffic.pcapng

# Carve file biner dari traffic jaringan:
pcapfile traffic.pcapng -o ./extracted_files

# Follow TCP stream #2 secara visual atau hex dump:
pcapstream traffic.pcapng -s 2
pcapstream traffic.pcapng -s 2 --hex

# Ekstraksi DNS Tunneling & Port Covert Channels:
pcappayload exfil.pcap --dns --domain evil.corp
pcapportpayload covert.pcap --port-ascii
```

---

### 3. 🧠 Modul Windows Memory Forensics (`dmp/`)
Analisis proses dan crash dump Windows (`.dmp`, `.raw`, `.bin`):
- **`memcarve`** (Rust ⚡): Universal Raw Memory Carver & Heuristic Multi-Page Assembler.
  - Carve format biner (DEX, ELF, PE, ZIP, dll.) langsung dari raw RAM.
  - Rekonstruksi halaman alokasi memori berurutan terbalik (*LIFO reverse page allocation*) maupun linear.
  - Mode kamus header: `memcarve dict` untuk melihat 15+ signature bawaan.
  - Mode context: `memcarve context` untuk hexdump & string di sekitar physical offset.
- **`volrust`** (`vol-rs`): Volatility 3 berbasis Rust untuk eksekusi plugin kilat (`windows.pslist`, `windows.malfind`, `windows.netscan`).
- **`dmpscan`**: Full automated triage memori Windows (PEB, loaded modules, dan flag hunter).
- **`dmpdump`**: Targeted memory & binary dumper (Dump via Base Address `-i`, Module Name `-m`, atau Main Executable `--main`).
- **`dmppeb`**: Rekonstruksi *Process Environment Block* (PID, Process Name, Arsitektur, Command Line, Env Variables - setara `!peb` WinDbg).
- **`dmpmodules`**: Pemetaan library & executable yang dimuat (Base Address, Size, Version - setara `lm` WinDbg).
- **`dmpflags`**: Deep flag hunter di seluruh committed virtual memory (ASCII, UTF-16LE, Base64).

```bash
# Memcarve biner DEX yang memuat string target (dengan reverse-page assembler):
memcarve scan chall.raw DEX "api/v1" --extract ./carved_dex

# Memcarve semua format header yang mengandung kata kunci:
memcarve scan chall.raw -a "flag" --extract ./carved_all

# Menampilkan kamus signature header:
memcarve dict

# Eksekusi Volatility Rust ultra-cepat:
volrust -f memory.raw windows.pslist
volrust -f memory.raw windows.malfind

# Analisis DMP Windows Minidump:
dmpscan DbgInfo.DMP
dmpdump DbgInfo.DMP --main -o ./DbgInfo.exe
dmppeb DbgInfo.DMP
dmpmodules DbgInfo.DMP
```

---

### 4. 🐧 Modul Linux LiME Memory Forensics (`lime/`)
Analisis memori Linux LiME RAM dumps (`.lime`, `.mem`, `.raw`):
- **`limescan`**: Memindai kernel release banner (misal `5.15.0-generic`), arsitektur (x64/ARM64), dan mencocokkan secara offline dengan 10.000+ katalog Intermediate Symbol Format (ISF).
- **`limebuild`**: Download otomatis vmlinux/dwarf dan kompilasi symbol tables `.json.xz` yang kompatibel dengan Volatility 3.
- **`limefast`**: Native C++17 symbol-free memory scanner. Melakukan inspeksi proses, modul kernel, dan koneksi jaringan langsung dari physical RAM tanpa memerlukan file simbol debugging.

```bash
# Identifikasi kernel banner & rekomendasi ISF:
limescan memory.lime

# Build symbol table Volatility 3:
limebuild memory.lime --isf ./downloaded-kernel.json.xz

# Symbol-free fast triage:
limefast memory.lime --pslist
```

---

### 5. 🛠️ Modul Assembly & Reverse Engineering (`assembly/`)
Suite lengkap reverse engineering, binary doctor, disassembler, dan Ghidra live companion:
- **`ghidraanalyze`** (`ghidracli`): Jembatan interaktif 2 arah ke Ghidra GUI Windows (`status`, `goto <addr>`, `current`, `callers`, `callees`, `vars`, `decompile`, `rename`, `comment`).
- **`exefix`** & **`exedoctor`**: Realign section memory dump PE Windows, diagnosa kerusakan header PE, perbaiki Virtual Address, dan hilangkan prefix shellcode/trailing overlay.
- **`ghidraguide`**: Menghasilkan peta navigasi reversing Ghidra, checklist analisis, dan blueprint writeup otomatis.
- **`elfdoctor`**: Diagnosa integritas file Linux ELF (header `\x7fELF`, arsitektur, endianness, stripped symbols, UPX packing).
- **`disasm`** (`shellcode`): Multi-arch raw shellcode disassembler (x64, x86, ARM, ARM64) dengan auto-deteksi PEB walking (`gs:[0x60]` / `fs:[0x30]`), NOP sleds, dan ROR13 API hashes.

```bash
# Interaksi 2 arah dengan Ghidra GUI:
ghidraanalyze status
ghidraanalyze goto 0x14000115a
ghidraanalyze current
ghidraanalyze callers 0x140001090
ghidraanalyze rename 0x140001090 rc4_shellcode_launcher

# Perbaiki memory dump Windows PE untuk decompilasi Ghidra bersih:
exefix DbgInfo_dumped.exe -o ./DbgInfo_fixed.exe
exedoctor malware.exe
ghidraguide malware.exe

# Diagnosa Linux ELF & Disassemble Shellcode:
elfdoctor suspicious.elf
disasm shellcode.bin -a x64
```

---

### 6. 🔐 Modul Cryptography & Obfuscation (`cipher/`)
Analisis otomatis, deteksi jenis cipher, key harvesting, dan template decrypter siap pakai:
- **`ciphercheck`**: Analisis pintar format encoding (Base64/Hex/URL/Binary/Decimal), entropi Shannon, deteksi algoritma (AES-ECB/CBC/CTR, DES, ChaCha20, RC4, RSA, Hashes), dan auto-XOR hunter.
  - **Interactive Mode**: Jalankan `ciphercheck` tanpa argumen untuk langsung paste payload via terminal.
- **`cryptohunt`** (`keyhunt`): **Cryptographic Key, Nonce, Constant & Struct Harvester**.
  - Pindai kandidat Key 32-byte / 16-byte, Nonce 12-byte / 8-byte, dan konstanta algoritma (`expand 32-byte k`, AES S-Boxes, SHA constants).
  - Ekstraksi pasangan struct kriptografi terorganisir `{Nonce, Key}` (`--pair`).
  - **Auto Test Decrypt**: Otomatis uji dekripsi kandidat kunci terhadap ciphertext (`--test-decrypt "<ciphertext>"` `--prefix "CTF{"`).
- **Template Script Siap Pakai (`T_*.py`)**:
  - `T_aes.py`: AES Swiss-army knife (ECB, CBC, CTR, GCM, auto-IV).
  - `T_chacha20.py`: ChaCha20 & Salsa20 stream cipher toolkit.
  - `T_xor.py`: Single-byte brute force, repeating XOR, dan rolling seed XOR.
  - `T_rc4.py`: RC4 / ARC4 stream cipher toolkit.
  - `T_rsa.py`: RSA attack toolkit (Wiener, Fermat, FactorDB).
  - `T_classical.py`: Caesar ROT-1 s/d ROT-25, Vigenere, Atbash, Rail Fence.

```bash
# Identifikasi otomatis jenis cipher & encoding:
ciphercheck -t "ZGNSdmFXVCJYVAFvYj2Pvf24Ac72V8EHi2Rl3BgtGYk="
ciphercheck -i cipher.txt

# Panen Key/Nonce kriptografi & auto-test dekripsi dari biner/memori:
cryptohunt malware.elf --pair --test-decrypt "KEVt/ztn..." --prefix "FLAG{"
cryptohunt memory.lime --near "expand 32-byte k" --range 65536

# Eksekusi template decrypter:
python3 /mnt/d/tools/cipher/T_aes.py -k "ZjLtHquGbCxfsnoS" -i payload.b64 -m CTR
python3 /mnt/d/tools/cipher/T_xor.py -i obfuscated.bin --brute
```

---

### 7. 🖼️ Modul Steganography & Audio (`stego/`)
Deteksi otomatis dan pemecahan steganografi multi-layer pada file gambar, audio, dan biner:
- **`stegoscan`**: Diagnosa chunk PNG non-standar (`raCh`, `prIv`), perbaiki PNG IHDR height mismatch (`--fix-height`), deteksi trailing overlay bytes past `IEND`/`FF D9`, dan auto-carve embedded file (ZIP, 7z, RAR, PDF, PE, ELF).
- **`stegodiff`**: Auto-bruteforce pergeseran matriks 2D $(dx, dy)$ antara 2 gambar, decode residual arithmetic delta ($\Delta = 1, 2$) jadi biner/ASCII, dan ekstrak modulasi border bitstream.
- **`stegocrack`**: Automated password cracking untuk Steghide (blank password, common CTF wordlists, custom dictionary) dan OutGuess.
- **`stegoaudio`**: High-resolution FFT frequency spectrogram visualizer (`.wav`, `.mp3`, `.ogg`, `.flac`) untuk mengungkap visual morse/teks rahasia di spektrum suara, serta ekstraksi WAV sample LSB.

```bash
# Periksa & perbaiki header PNG:
stegoscan image.png --fix-height
stegoscan payload.jpg --carve ./carved_files

# Analisis perbedaan visual 2 gambar:
stegodiff preview.png reference.png

# Crack password steghide:
stegocrack secret.jpg -w /usr/share/wordlists/rockyou.txt

# Spektrogram audio FFT:
stegoaudio recording.wav -o ./spectrogram.png
```

---

### 8. 🗂️ Modul AD1 Forensics (`ad1/`)
Analisis mendalam citra logikal AccessData (`.ad1`, `.ad2`):
- **`ad1history`**: Ekstraksi browser history (Chrome, Edge, Firefox, Brave, Safari) + auto-korelasi & ekstraksi bundle DPAPI.
- **`ad1dpapi`**: Automated DPAPI MasterKey recovery & Chromium password decryption offline via Plain Password (`-p`), NTLM hash (`--ntlm`), Wordlist/Rockyou (`-w`), atau auto-extract SAM/SYSTEM (`--auto-sam`).
- **`ad1amcache`**: Analisis eksekusi program Windows via `Amcache.hve`.
- **`ad1ntuser`**: Analisis aktivitas user via `NTUSER.DAT` (UserAssist, TypedPaths, RunMRU, RecentDocs).
- **`ad1recent`**: Analisis shortcut `.lnk` dan Windows JumpLists.
- **`ad1extensions`**: Triage ekstensi browser & deteksi ekstensi terhapus (*Orphan storage*) via LevelDB parser.
- **`ad1scan`**: Visual folder tree direktori user dengan auto-highlight file sensitif & flag.
- **`ad1scandetail`**: Zero-noise user documents, notes, dan photos hunter (mengecualikan `AppData`).

```bash
# Browser history & DPAPI offline decryption:
ad1history evidence.ad1 -p "Password123"
ad1dpapi evidence.ad1 -w /usr/share/wordlists/rockyou.txt

# Amcache & User Activity:
ad1amcache evidence.ad1
ad1ntuser evidence.ad1
ad1recent evidence.ad1

# Scan file sensitif & user documents:
ad1scan evidence.ad1 --sensitive-only
ad1scandetail evidence.ad1 -u SERV
```

---

## 🎯 Master Cheatsheet & CLI Reference

Gunakan cheatsheet berikut untuk referensi cepat semua perintah:

| Kategori | Perintah / Shorthand | Deskripsi Singkat |
| :--- | :--- | :--- |
| **Bantuan** | `tools --help` | Bantuan master seluruh toolkit |
| **Bantuan Modul** | `tools <pcap\|dmp\|lime\|assembly\|cipher\|stego\|ad1\|core> --help` | Bantuan detail per modul |
| **Universal ⚡** | `globalscan2 <file>` | Scan flags, hashes, metadata & XOR brute-force (Rust) |
| **Universal ⚡** | `strings2 <file> -s "str" -C 2` | Ekstraksi strings dengan regex & context lines (Rust) |
| **Universal ⚡** | `binwalk2 <file> -e -o ./out` | SIMD firmware & binary signature carver (Rust) |
| **PCAP 🌐** | `pcapendpoint <file.pcap>` | Deteksi C2, Flag, Seed, Exfil & Fake Telemetry otomatis |
| **PCAP 🌐** | `pcapendpoint <file.pcap> -s <ID>` | Follow percakapan request-response stream tertentu |
| **PCAP 🌐** | `pcapfirst <file.pcap>` | Macro triage dashboard & protocol hierarchy |
| **PCAP 🌐** | `pcaptree <file.pcap>` | Visualisasi pohon protokol & tabel top talkers |
| **PCAP 🌐** | `pcapfile <file.pcap> -o ./out` | Carve & rekonstruksi file yang ditransfer |
| **PCAP 🌐** | `pcapstream <file.pcap> -s <ID>` | Wireshark-style follow stream bidirectional |
| **PCAP 🌐** | `pcapstream <file.pcap> -s <ID> --hex` | Hex & ASCII side-by-side dump |
| **PCAP 🌐** | `pcapscan <file.pcap>` | Threat & flag hunter seluruh stream |
| **PCAP 🌐** | `pcapscanstream <file.pcap>` | Deep stream scanner dengan auto XOR brute-force |
| **PCAP 🌐** | `pcappayload <file.pcap> --dns` | Ekstraksi subdomains DNS tunneling & auto-decode |
| **PCAP 🌐** | `pcapportpayload <file.pcap>` | Port-to-ASCII covert channel decoder |
| **Memory 🧠** | `memcarve scan <raw> DEX "api"` | Raw memory carver dengan LIFO reverse page assembler (Rust) |
| **Memory 🧠** | `memcarve scan <raw> -a "flag"` | Scan seluruh 15 signature header di memori (Rust) |
| **Memory 🧠** | `memcarve dict` | Tampilkan kamus signature header bawaan (Rust) |
| **Memory 🧠** | `volrust -f <raw> <plugin>` | Volatility 3 Rust port (20x - 500x faster) |
| **Memory 🧠** | `dmpscan <file.dmp>` | Triage memori Windows: PEB, modules, flag hunt |
| **Memory 🧠** | `dmpdump <file.dmp> --main` | Carve & dump executable utama dari memori |
| **Memory 🧠** | `dmppeb <file.dmp>` | Rekonstruksi PEB (command line, environment vars) |
| **Memory 🧠** | `dmpmodules <file.dmp>` | Loaded DLLs & Executables matrix (`lm`) |
| **Linux LiME 🐧** | `limescan <file.lime>` | Identifikasi Linux kernel release & matching ISF |
| **Linux LiME 🐧** | `limebuild <file.lime> --isf <sym>`| Download & build Volatility 3 symbol table |
| **Linux LiME 🐧** | `limefast <file.lime> --pslist` | Symbol-free Linux RAM inspection (C++17) |
| **Reversing 🛠️** | `ghidraanalyze status` | Cek jembatan live ke Ghidra GUI Windows |
| **Reversing 🛠️** | `ghidraanalyze goto <addr>` | Pindahkan layar & kursor Ghidra GUI |
| **Reversing 🛠️** | `ghidraanalyze current` | Decompile fungsi di posisi kursor Ghidra |
| **Reversing 🛠️** | `exefix <dumped.exe> -o <out>` | Realign section header PE dump memori |
| **Reversing 🛠️** | `exedoctor <file.exe>` | Diagnosa kerusakan PE header & sections |
| **Reversing 🛠️** | `ghidraguide <file.exe>` | Blueprint analisis Ghidra & checklist Writeup |
| **Reversing 🛠️** | `elfdoctor <binary.elf>` | Diagnosa Linux ELF: stripped symbols, UPX |
| **Reversing 🛠️** | `disasm <payload.bin> -a x64` | Disassemble shellcode x64/x86/ARM |
| **Crypto 🔐** | `ciphercheck` | Mode interaktif analisa jenis cipher & encoding |
| **Crypto 🔐** | `ciphercheck -t "<string>"` | Inspeksi string ciphertext langsung di terminal |
| **Crypto 🔐** | `cryptohunt <file> --pair` | Panen Key 32B/16B, Nonce & konstanta crypto |
| **Crypto 🔐** | `cryptohunt <file> --test-decrypt <ct>` | Auto-test kandidat kunci terhadap ciphertext |
| **Stego 🖼️** | `stegoscan <image.png> --fix-height` | Perbaiki PNG IHDR height mismatch (CRC) |
| **Stego 🖼️** | `stegodiff <img1> <img2>` | Auto-bruteforce shift 2D & residual delta |
| **Stego 🖼️** | `stegocrack <secret.jpg> -w <dict>` | Cracking password Steghide & OutGuess |
| **Stego 🖼️** | `stegoaudio <sound.wav>` | Visualisasi spektrogram suara FFT resolusi tinggi |
| **AD1 📂** | `ad1history <file.ad1>` | Ekstraksi database browser & DPAPI bundle |
| **AD1 📂** | `ad1dpapi <file.ad1> -p <pass>` | Dekripsi offline password browser via DPAPI |
| **AD1 📂** | `ad1amcache <file.ad1>` | Analisis artefak eksekusi program Amcache.hve |
| **AD1 📂** | `ad1ntuser <file.ad1>` | Analisis registry UserAssist, TypedPaths, RunMRU |
| **AD1 📂** | `ad1recent <file.ad1>` | Analisis shortcut LNK & JumpLists |
| **AD1 📂** | `ad1extensions <file.ad1>` | Triage ekstensi browser & orphan storage |
| **AD1 📂** | `ad1scan <file.ad1>` | Folder tree visual & penandaan file sensitif |
| **AD1 📂** | `ad1scandetail <file.ad1> -u <user>` | Pencarian dokumen & foto pengguna tanpa noise |

---

## 🚀 Setup & Instalasi Alias di WSL Ubuntu

```bash
# Setup alias sekali di awal:
bash /mnt/d/tools/install_alias.sh
source ~/.bashrc

# Verifikasi semua tools:
tools --help
memcarve --help
pcapendpoint --help
```
