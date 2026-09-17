# PCAP Forensics Suite Documentation

Suite alat analisis lalu lintas jaringan dan paket capture (**`.pcap`**, **`.pcapng`**, **`.cap`**) berbasis **Pure Python** berkinerja tinggi. Mampu membaca format PCAP klasik maupun PCAP Next Generation (.pcapng), merekonstruksi stream TCP secara bidirectional, melakukan inspeksi protokol (HTTP, TLS, DNS, ICMP, SSH, FTP, SMTP), mengekstrak artefak file, serta memburu payload tersembunyi dan CTF flags.

---

##  Daftar Isi
1. [Daftar Tools & Kegunaan](#1-daftar-tools--kegunaan)
2. [Opsi Ekspor File Laporan (MD, JSON, CSV)](#2-opsi-ekspor-file-laporan)
3. [Syntax & Contoh Menjalankan Tools](#3-syntax--contoh-menjalankan-tools)
   - [pcaptree (Hierarchy, Endpoints & Streams)](#a-pcaptree--hierarchy-endpoints--streams)
   - [pcapfile (File Extractor & Stream Carver)](#b-pcapfile--file-extractor--stream-carver)
   - [pcapstream (Wireshark-Style Stream Follower & Dumper)](#c-pcapstream--wireshark-style-stream-follower--dumper)
   - [pcapscan (C2 Fingerprints, Flag Hunter & Unpacker)](#d-pcapscan--c2-fingerprints-flag-hunter--unpacker)
4. [Cara Menjalankan di WSL Ubuntu & Windows](#4-cara-menjalankan-di-wsl-ubuntu--windows)

---

## 1. Daftar Tools & Kegunaan

| Nama Tool | Target Artefak | Deskripsi & Informasi yang Diekstrak |
| :--- | :--- | :--- |
| **`pcapendpoint`** | Stream HTTP, C2, DNS | **Endpoint Discovery & Automated Threat Triage**: <br>• **Threat Classification**: Auto-triage endpoint mencurigakan (C2 beaconing, flag bocor, parameter seed/secret, payload eksfiltrasi, port non-standar).<br>• **Fake Telemetry Masquerade Detector**: Deteksi domain telemetri palsu yang meniru vendor OS resmi.<br>• **Recursive Multi-Base Unpacker**: Otomatis decode Base64, Base32, Hex, URL-encoding pada path, query string, dan JSON body.<br>• **Entropy Scoring**: Deteksi URL dengan enkripsi atau DGA.<br>• **Follow Stream (`-s <ID>`)**: Langsung tampilkan percakapan request-response stream tertentu. |
| **`pcapfirst`** | `capture.pcap`, `traffic.pcapng` | **Instant Macro Triage & Structure Dashboard**: <br>• **Capture Overview**: Metadata, total volume, time span, durasi rekaman, dan protokol paling dominan.<br>• **Protocol Hierarchy (PHS)**: Statistik layer protokol lengkap.<br>• **Port Classification**: Pemetaan port standar vs port kustom/non-standar (*Red Alert*).<br>• **Top Conversations**: Pemetaan heavy-talkers 5-tuple dengan resolusi Host/SNI/WebSocket.<br>• **Auto-Suggested Next Steps**: Rekomendasi perintah drilldown otomatis. |
| **`pcaptree`** | `capture.pcap`, `traffic.pcapng` | **Triage Cepat Struktur PCAP**: Menampilkan visualisasi pohon distribusi protokol (*Protocol Hierarchy Tree*), tabel *Top Talkers Endpoints* (Tx/Rx Packets & Bytes), serta daftar seluruh percakapan *TCP/UDP Streams* dengan resolusi SNI, HTTP Request URI, dan ringkasan percakapan. |
| **`pcapfile`** | Stream TCP, HTTP, FTP | **Reconstructor & File Carver**: Mengekstrak file yang ditransfer melalui jaringan (HTTP downloads/POST responses, Content-Disposition, URI filenames, decompressed bodies) serta *Magic Carving* otomatis pada payload mentah (WebAssembly `.wasm`, Windows PE `.exe`, Linux `.elf`, `.zip`, `.pdf`, `.png`, `.jpg`, `.sqlite`, `.sh`) dengan opsi ekspor langsung ke direktori lokal (`-o / --export-dir`). |
| **`pcapstream`** | Stream TCP tertentu | **Wireshark-Style Follow Stream**: Menampilkan percakapan stream dua arah secara visual dengan pewarnaan terpisah (Client  Server: Cyan, Server  Client: Hijau), mode *Hex Dump* 16-byte berdampingan, pencarian teks global pada seluruh stream (`--search`), dan ekspor biner mentah (`--export-dir`). |
| **`pcapscan`** | Seluruh Packet Streams | **Threat & Flag Hunter**: <br>• **CTF Flag Hunter**: Pencarian regex flag standar dan custom prefix.<br>• **C2 Framework Fingerprinting**: Otomatis mengenali pola endpoint C2 populer (NimPlant, Cobalt Strike, Sliver, Havoc, Mythic, Metasploit).<br>• **High-Entropy Encrypted C2 Detector**: Alert stream terenkripsi/ciphertext (Entropy > 7.6).<br>• **Recursive Multi-Layer Unpacker**: Dekompresi bertingkat (Base64  Gzip  Base64  Flag/Payload).<br>• **Covert Channels**: Deteksi DNS Tunneling/Exfiltration dan ICMP Data Tunneling. |
| **`pcapscanstream`** | Stream TCP, UDP, ICMP | **Deep Stream & Custom Payload Scanner**: <br>• **Protocol Filter**: Inspeksi stream per protokol (`-tcp`, `-udp`, `-icmp`, `-all`).<br>• **Custom & Proprietary Header Detector**: Mengenali header non-standar/C-struct (misal `OVSH1`, `BAM2`, `CHCK`, dll).<br>• **High-Entropy / Ciphertext Detector**: Menghitung Shannon Entropy per stream ($H > 7.2$) untuk mendeteksi payload terenkripsi (ChaCha20, AES-CTR).<br>• **Auto XOR Brute-Force**: Tes key `0x01`..`0xFF` untuk membongkar obfuscated stream.<br>• **WebSocket RFC 6455 Unmasker**: Unmasking payload teks & binary WebSocket frame.<br>• **Stream Drilldown**: Inspeksi detail hex/ASCII stream tertentu (`-s <ID>`). |
| **`pcappayload`** | Paket TCP, UDP, ICMP, DNS | **Packet Payload Reassembler & Fragmented Stream Extractor**: Ekstraksi data payload per-paket (per-baris), rekonstruksi eksfiltrasi data terfragmentasi (DNS tunneling, ICMP echo data, UDP/TCP raw stream), dan auto-decoding Base64/Hex/Base32/URL. |
| **`pcapportpayload`** | Seluruh Paket & Header | **Port Manipulation & Covert Channel Decoder**: <br>• **Port-to-ASCII Decoder**: Deteksi urutan port tujuan/sumber berurutan yang meng-encode karakter ASCII/flag (1-byte, 2-byte BE/LE).<br>• **Per-Packet Discrete Reassembler**: Menggabungkan data diskrit per-paket pada port tertentu.<br>• **IP Header Covert Channel**: Mengekstrak data tersembunyi dari field `IP.ID` dan `TTL`.<br>• **Suspicious Port Profiling**: Pemetaan port-port anomali/CTF backdoor. |

---

## 2. Opsi Ekspor File Laporan

| Flag Argumen | Format | Keunggulan & Karakteristik |
| :--- | :---: | :--- |
| **`--md <file.md>`** / **`--markdown <file.md>`** | **Markdown** | Bersih, rapi, mudah dibaca langsung di terminal/GitHub/editor teks, cocok untuk Writeup (WU). |
| **`--json <file.json>`** | **JSON** | Terstruktur, mudah diintegrasikan dengan skrip automasi Python/jq atau pipeline investigasi. |
| **`--export-all`** | **Semua** | Menghasilkan file **`.md`**, **`.json`**, dan mengekstrak file/artefak biner sekaligus ke direktori lokal. |

---

## 3. Syntax & Contoh Menjalankan Tools

### A. `pcaptree` – Hierarchy, Endpoints & Streams

Visualisasi struktur PCAP, protocol distribution, dan pemetaan percakapan network.

#### Syntax Lengkap:
```bash
pcaptree <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `--proto <nama_protokol>` : Filter daftar stream berdasarkan protokol (misal: `HTTP`, `TLS`, `SSH`, `FTP`).
- `--ip <alamat_ip>` : Filter stream dan tabel endpoints berdasarkan IP tertentu.
- `-l`, `--limit <jumlah>` : Batas jumlah baris tabel yang ditampilkan (default: 50).
- `--md <output.md>` : Ekspor laporan ke file Markdown.
- `--json <output.json>` : Ekspor laporan ke file JSON.
- `--export-all` : Ekspor seluruh laporan secara otomatis.

#### Contoh Penggunaan:
```bash
# 1. Triage awal: Lihat protocol hierarchy & top endpoints
pcaptree capture.pcapng

# 2. Filter hanya stream protokol HTTP
pcaptree capture.pcapng --proto HTTP

# 3. Filter percakapan yang melibatkan IP tertentu
pcaptree capture.pcapng --ip 10.0.2.15

# 4. Ekspor hasil analisis tree ke Markdown dan JSON
pcaptree capture.pcapng --export-all
```

---

### B. `pcapfile` – File Extractor & Stream Carver

Mengekstrak file yang dikirim lewat HTTP/FTP atau tersembunyi di dalam stream payload.

#### Syntax Lengkap:
```bash
pcapfile <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `-o`, `--out`, `--export-dir <folder>` : Simpan seluruh file yang terdeteksi ke direktori lokal.
- `-i`, `--index <nomor_file>` : Ekstrak hanya file dengan index tertentu (misal: `-i 1`).
- `--md <output.md>` : Ekspor daftar file dan hash ke file Markdown.
- `--json <output.json>` : Ekspor daftar file ke file JSON.
- `--export-all` : Simpan semua file ke folder dan buat laporan Markdown + JSON.

#### Contoh Penggunaan:
```bash
# 1. Scan dan tampilkan daftar file yang ditemukan di dalam PCAP
pcapfile capture.pcapng

# 2. Ekstrak semua file ke folder ./extracted_files
pcapfile capture.pcapng -o ./extracted_files

# 3. Ekstrak hanya file #1 ke folder ./carved_output
pcapfile capture.pcapng -i 1 -o ./carved_output

# 4. Ekspor semua file beserta laporan metadata lengkap
pcapfile capture.pcapng --export-all
```

---

### C. `pcapstream` – Wireshark-Style Stream Follower & Dumper

Melihat isi percakapan stream tertentu secara interaktif atau mengekstrak raw binary stream.

#### Syntax Lengkap:
```bash
pcapstream <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `-s`, `--stream <nomor_stream>` : Nomor ID stream yang ingin diikuti (misal: `-s 2`).
- `--hex` : Tampilkan payload dalam format 16-byte Hex Dump + ASCII preview.
- `--side [both|client|server]` : Filter arah payload (Client  Server atau Server  Client).
- `--search "<keyword>"` : Cari kata kunci tertentu di seluruh percakapan stream.
- `-o`, `--out`, `--export-dir <folder>` : Ekstrak payload client, server, dan full stream ke file biner `.bin`.

#### Contoh Penggunaan:
```bash
# 1. Follow percakapan Stream #2 (Interleaved conversation text)
pcapstream capture.pcapng -s 2

# 2. Tampilkan Stream #2 dalam format Hex Dump
pcapstream capture.pcapng -s 2 --hex

# 3. Hanya tampilkan payload yang dikirim dari Client ke Server
pcapstream capture.pcapng -s 2 --side client

# 4. Cari kata kunci "password" atau "login" di seluruh stream
pcapstream capture.pcapng --search "login"

# 5. Ekstrak payload Stream #2 ke file biner mentah (.bin)
pcapstream capture.pcapng -s 2 -o ./stream_payloads
```

---

### D. `pcapscan` – Threat, C2 Fingerprint & Flag Hunter

Menganalisis payload untuk menemukan CTF flags, indikator serangan, C2, dan covert channels.

#### Syntax Lengkap:
```bash
pcapscan <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `-p`, `--prefix "<prefix>"` : Prefix custom untuk pencarian flag (misal: `-p "FLAG"`, `-p "cyber"`).
- `--flags-only` : Hanya tampilkan flag CTF yang ditemukan.
- `--findings-only` : Hanya tampilkan alert dan indikator serangan.
- `-l`, `--limit <jumlah>` : Batas jumlah temuan yang ditampilkan (default: 50).
- `--md <output.md>` : Ekspor laporan temuan ke Markdown.
- `--json <output.json>` : Ekspor laporan temuan ke JSON.
- `--export-all` : Ekspor laporan temuan ke MD dan JSON.

#### Contoh Penggunaan:
```bash
# 1. Full scan ancaman & CTF flags
pcapscan capture.pcapng

# 2. Cari flag dengan prefix custom
pcapscan capture.pcapng -p "CTF{"

# 3. Hanya tampilkan tabel flag yang berhasil ditangkap
pcapscan capture.pcapng --flags-only

# 4. Ekspor seluruh temuan ke laporan Markdown & JSON
pcapscan capture.pcapng --export-all
```

---

### E. `pcappayload` – Packet Payload Reassembler & Fragmented Stream Extractor

Mengekstrak data payload per-paket (per-baris), merekonstruksi eksfiltrasi data terfragmentasi (*DNS tunneling, ICMP echo data, UDP/TCP raw stream*), dan *auto-decoding* Base64/Hex/Base32/URL.

#### Syntax Lengkap:
```bash
pcappayload <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `-m`, `--mode {lines,concat,dns,icmp,raw}` : Mode ekstraksi (default: `lines`).
- `-c`, `--concat` : Gabungkan seluruh payload paket menjadi satu aliran data kontinu.
- `--dns` : Otomatis ekstrak subdomain dari kueri DNS, hapus suffix domain target, dan decode eksfiltrasi.
- `--icmp` : Ekstrak deretan payload data dari paket ICMP Ping (Echo Request/Reply).
- `-d`, `--decode` : Auto-decode string gabungan (Hexadecimal, Base64, Base32, URL decode).
- `--ip <IP>` / `--port <PORT>` : Filter paket berdasarkan IP atau port tertentu.
- `--domain <domain>` : Suffix domain dasar yang ingin dibersihkan pada mode DNS (misal: `evil.corp`).
- `--unique` : Hapus baris payload duplikat yang berurutan.
- `-o`, `--output <file>` : Simpan hasil ekstraksi payload ke file lokal.

#### Contoh Penggunaan:
```bash
# 1. Tampilkan payload per-paket baris demi baris:
pcappayload capture.pcap --port 4444

# 2. Ekstrak & decode data eksfiltrasi DNS Tunneling:
pcappayload exfil.pcap --dns --domain evil.corp

# 3. Ekstrak dan susun payload paket ICMP Ping:
pcappayload ping.pcap --icmp -c -o ./extracted_icmp.bin

# 4. Filter berdasarkan IP, gabungkan stream, dan auto-decode Hex/Base64:
pcappayload capture.pcap --ip 10.0.0.5 -c -d
```

---

### F. `pcapportpayload` – Port Manipulation & Covert Channel Decoder

Menganalisis manipulasi nomor port (Port-to-ASCII), header IP/TTL covert channels, dan rekonsiliasi data per-paket per-port.

#### Syntax Lengkap:
```bash
pcapportpayload <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `--port <PORT>` : Filter inspeksi hanya pada port tertentu.
- `-l`, `--limit <jumlah>` : Batas jumlah baris tabel yang ditampilkan (default: 30).
- `--flags-only` : Hanya tampilkan flag yang berhasil ditemukan.
- `--md <output.md>` : Ekspor laporan temuan ke Markdown.
- `--json <output.json>` : Ekspor laporan temuan ke JSON.
- `--export-all` : Ekspor seluruh laporan secara otomatis.

#### Contoh Penggunaan:
```bash
# 1. Full scan covert channel port & per-packet data:
pcapportpayload covert_traffic.pcap

# 2. Filter analisis hanya pada port tertentu (misal: port 1337):
pcapportpayload covert_traffic.pcap --port 1337

# 3. Hanya tampilkan flag CTF yang berhasil diekstrak:
pcapportpayload covert_traffic.pcap --flags-only

# 4. Ekspor seluruh laporan analisis ke Markdown dan JSON:
pcapportpayload covert_traffic.pcap --export-all
```

---

### G. `pcapendpoint` – Endpoint Discovery & Automated Threat Hunter

Memindai seluruh stream HTTP/HTTPS untuk mendeteksi endpoint C2 berbahaya, kebocoran flag/secret, parameter seed, payload eksfiltrasi, serta domain penyamaran telemetri palsu (*Fake Telemetry Masquerade*).

#### Syntax Lengkap:
```bash
pcapendpoint <capture.pcap|capture.pcapng> [opsi]
```

#### Opsi yang Tersedia:
- `-s`, `--stream <ID>` : Follow percakapan dua arah (request + response) untuk TCP Stream ID tertentu.
- `-a`, `--all` : Tampilkan seluruh endpoint termasuk background telemetri OS normal.
- `-q`, `--search <QUERY>` : Filter endpoint berdasarkan kata kunci (URL, Host, Param).
- `-m`, `--method <METHOD>` : Filter berdasarkan HTTP method (`GET`, `POST`, dll.).
- `-o`, `--export-dir <DIR>` : Folder tujuan untuk mengekspor payload dari stream yang mencurigakan.

#### Contoh Penggunaan:
```bash
# 1. Scan otomatis seluruh stream & tampilkan triage endpoint mencurigakan:
pcapendpoint wire.pcap

# 2. Follow percakapan request-response stream #49:
pcapendpoint wire.pcap -s 49

# 3. Tampilkan semua endpoint tanpa filter telemetri OS:
pcapendpoint wire.pcap --all

# 4. Cari endpoint yang mengandung string API tertentu:
pcapendpoint wire.pcap -q "api/v1"

# 5. Export seluruh stream mencurigakan ke folder:
pcapendpoint wire.pcap -o ./c2_dumps
```

---

## 4. Cara Menjalankan di WSL Ubuntu & Windows

### Via Alias Global (WSL / Linux)
```bash
# Aktifkan alias sekali di awal:
bash /mnt/d/tools/install_alias.sh
source ~/.bashrc

# Jalankan langsung command:
pcaptree capture.pcapng
pcapfile capture.pcapng -o ./carved
pcapstream capture.pcapng -s 2 --hex
pcapscan capture.pcapng
```

### Via Master Dispatcher (`tools.py`)
```bash
python3 tools.py pcap tree capture.pcapng
python3 tools.py pcap file capture.pcapng -o ./carved
python3 tools.py pcap stream capture.pcapng -s 2
python3 tools.py pcap scan capture.pcapng
```
