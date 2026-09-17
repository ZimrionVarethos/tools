#  PLAYBOOK FINAL DIGITAL FORENSICS CTF
##  Panduan Taktis 7 Chapter Skenario Terintegrasi

---

##  MEKANISME & STRUKTUR FINAL
1. **Format**: 7 Chapter Terintegrasi (Masing-masing 3–6 soal).
2. **Durasi**: 4–6 Jam Penuh.
3. **Prinsip Utama (Chain-Dependency)**: 
   >  Temuan/Flag dari Chapter $N$ **hampir selalu menjadi Password / Kunci Dekripsi / IP / User / Parameter** untuk membuka artefak di Chapter $N+1$.

---

##  PETA ARTEFAK & EKSEKUSI TOOLS (EVIDENCE PACK)

```text
EVIDENCE PACK
├── 1. Image Harddisk (.E01, .raw, .dd, .vmdk, .vhdx)  ──> AIM / TSK / Hayabusa / Chainsaw / Dissect
├── 2. Dump RAM (.raw, .vmem, .dmp)                     ──> Volatility 3 (vol) / strings / foremost
├── 3. Bin File / Payload (.bin, .exe, .elf)            ──> Binwalk / Radare2 / Pefile / Jadx
├── 4. Steganography (.png, .jpg, .wav, .zip)           ──> zsteg / stegseek / Exiftool / SoX / 7z
└── 5. Log Jaringan Perimeter (.pcap, .pcapng, .log)    ──> tshark / Wireshark / Python-dpkt / Scapy
```

---

# 1⃣ ARTEFAK 1: IMAGE HARDDISK TERSANGKA

### A. Format Berkas:
`.E01`, `.001`, `.raw`, `.dd`, `.vmdk`, `.vhdx`, `.img`

### B. Alur & Tools:
1. **Mounting Cepat**:
   * **Arsenal Image Mounter (AIM)** (Windows GUI) $\rightarrow$ Mount sebagai physical drive (misal `E:\`).
   * **WSL / Linux CLI**:
     ```bash
     # Mount berkas .E01
     mkdir -p /mnt/e01_raw /mnt/disk_mount
     ewfmount suspect_disk.E01 /mnt/e01_raw/
     mount -o ro,loop /mnt/e01_raw/ewf1 /mnt/disk_mount/
     ```
2. **Triage Instan tanpa Mount (Dissect Target)**:
   ```bash
   target-shell suspect_disk.E01
   target-query -f "SELECT * FROM os.users" suspect_disk.E01
   ```
3. **Analisis Event Logs Windows (`.evtx`)**:
   * **Hayabusa** (Auto Sigma Rule Detection):
     ```bash
     hayabusa csv-timeline -d "/mnt/disk_mount/Windows/System32/winevt/Logs" -o ./timeline.csv
     hayabusa logon-summary -d "/mnt/disk_mount/Windows/System32/winevt/Logs"
     ```
   * **Chainsaw**:
     ```bash
     chainsaw hunt "/mnt/disk_mount/Windows/System32/winevt/Logs" -s /usr/local/share/sigma/ --mapping /usr/local/share/chainsaw/mappings/sigma-event-logs-all.yml
     ```
   * **evtx_dump**:
     ```bash
     evtx_dump "/mnt/disk_mount/Windows/System32/winevt/Logs/Security.evtx" | grep -i "4624\|4625\|4672\|4688"
     ```
4. **Analisis Registry (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)**:
   ```bash
   # Dump Registry Key via python-registry
   python3 -c "from Registry import Registry; reg = Registry.Registry('/mnt/disk_mount/Windows/System32/config/SYSTEM'); print(reg.root().name())"
   ```
5. **Analisis File Terhapus & MFT**:
   * **The Sleuth Kit (TSK)**:
     ```bash
     mmls suspect_disk.raw                              # Cek tabel partisi & offset
     fls -o <OFFSET_PARTISI> -r -d suspect_disk.raw     # List file yang terhapus (d/d)
     icat -o <OFFSET_PARTISI> suspect_disk.raw <INODE> > recovered_file.bin
     ```
   * **analyzeMFT**:
     ```bash
     analyzeMFT.py -f "/mnt/disk_mount/\$MFT" -o ./mft_analysis.csv
     ```
6. **Recycle Bin & LNK Shortcuts**:
   * **rifiuti2**:
     ```bash
     rifiuti-vista -o recycle_analysis.txt "/mnt/disk_mount/\$Recycle.Bin"
     ```
   * **pylnk3**:
     ```bash
     pylnk3 dump "shortcut.lnk"
     ```

---

# 2⃣ ARTEFAK 2: DUMP RAM / MEMORY FORENSICS

### A. Format Berkas:
`.raw`, `.vmem`, `.dmp`, `.mem`, `.bin`

### B. Alur & Tools (Volatility 3 via `vol`):

1. **Info OS & Waktu Ekstraksi**:
   ```bash
   vol -f memdump.raw windows.info
   ```
2. **Command Line (Cari Script / Password / Argumen)**:
   ```bash
   vol -f memdump.raw windows.cmdline
   ```
3. **Pohon Proses & Deteksi Injeksi**:
   ```bash
   vol -f memdump.raw windows.pstree
   vol -f memdump.raw windows.malfind
   ```
4. **Koneksi Jaringan / C2 Active Sockets**:
   ```bash
   vol -f memdump.raw windows.netscan
   ```
5. **Pencarian File & Carving dari RAM**:
   ```bash
   # Cari file spesifik
   vol -f memdump.raw windows.filescan | grep -iE "flag|secret|pass|\.zip|\.pdf|\.kdbx"
   
   # Dump file fisik berdasarkan Virtual Address (0xda01...)
   vol -f memdump.raw -o ./dumped_files/ windows.dumpfiles --virtaddr 0xda01f822a100
   ```
6. **Dumping Memori Proses Tertentu (`memmap`)**:
   ```bash
   # Dump seluruh ruang memori proses PID 2104 (misal notepad/powershell/browser)
   vol -f memdump.raw -o ./dumped_proc/ windows.memmap --pid 2104 --dump
   
   # Bedah isi .dmp hasil memmap:
   strings -a -el ./dumped_proc/pid.2104.dmp | grep -iE "CTF\{|flag\{|password"   # Unicode UTF-16
   strings -a ./dumped_proc/pid.2104.dmp | grep -iE "CTF\{|flag\{|http"            # ASCII
   foremost -i ./dumped_proc/pid.2104.dmp -o ./carved_from_proc/                  # File Carving
   ```
7. **Ekstraksi SAM NTLM Hashes & LSA Secrets**:
   ```bash
   vol -f memdump.raw windows.hashdump
   vol -f memdump.raw windows.lsadump
   ```

---

# 3⃣ ARTEFAK 3: BIN FILE / FIRMWARE / PAYLOAD / SHELLCODE

### A. Format Berkas:
`.bin`, `.dat`, `.exe`, `.dll`, `.elf`, `.so`, `.apk`

### B. Alur & Tools:
1. **Identifikasi & File Carving**:
   ```bash
   file firmware.bin
   binwalk -e firmware.bin 2>/dev/null || foremost -i firmware.bin -o ./carved/
   ```
2. **Reverse Engineering & Disassembly**:
   * **Radare2 (r2)**:
     ```bash
     r2 -d -A malware.bin
     # Di dalam r2:
     # > afl        (list semua fungsi)
     # > pdf @main  (disassemble fungsi main)
     # > izz        (list semua string di binary)
     ```
   * **Pefile / Capstone**:
     ```bash
     python3 -c "import pefile; pe = pefile.PE('payload.exe'); print([s.Name.decode() for s in pe.sections])"
     ```
   * **Android APK**:
     ```bash
     jadx -d ./apk_source/ application.apk
     ```
3. **Office Macro & Embedded Payload**:
   * **oletools**:
     ```bash
     olevba suspicious_doc.docm
     mraptor suspicious_doc.docm
     ```

---

# 4⃣ ARTEFAK 4: STEGANOGRAPHY & CRYPTO

### A. Format Berkas:
`.png`, `.jpg`, `.bmp`, `.wav`, `.mp3`, `.pcap`, `.zip`, `.7z`, `.asc`, `.gpg`

### B. Alur & Tools:
1. **Gambar (PNG / BMP / JPG)**:
   * **zsteg** (Deteksi LSB Multi-plane, OpenStego, ExtData):
     ```bash
     zsteg -a evidence.png
     zsteg -E "b1,rgb,lsb,xy" evidence.png > extracted_payload.bin
     ```
   * **stegseek & steghide** (Cracking instan < 1 detik):
     ```bash
     stegseek evidence.jpg /usr/share/wordlists/rockyou.txt
     steghide extract -sf evidence.jpg -p "KATA_SANDI"
     ```
   * **Metadata & Trailer Carving**:
     ```bash
     exiftool -G1 -a -s evidence.png
     pngcheck -v evidence.png
     ```
2. **Audio Forensics (WAV / MP3 Spektrogram)**:
   ```bash
   # Visualisasi spektrum suara FFT (mencari tulisan tersembunyi)
   sox recording.wav -n spectrogram -o spectrogram.png
   ```
3. **Password Cracking (ZIP, 7z, Hash)**:
   * **John The Ripper / Hashcat**:
     ```bash
     zip2john secret.zip > zip.hash
     john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
     ```
   * **7z AES Extraction**:
     ```bash
     7z x -p"PASSWORD_DARI_SOAL_SEBELUMNYA" archive.zip -o./extracted/ -y
     ```
4. **PGP / GPG Decryption**:
   ```bash
   gpg --import private_key.asc
   gpg --batch --yes --decrypt message.asc
   ```

---

# 5⃣ ARTEFAK 5: LOG JARINGAN PERIMETER & PCAP

### A. Format Berkas:
`.pcap`, `.pcapng`, `.cap`, `.log`, `.csv`, `.json`

### B. Alur & Tools (`tshark` CLI Masterclass):

1. **Ringkasan Protokol & Percakapan IP**:
   ```bash
   tshark -r capture.pcap -q -z io,phs
   tshark -r capture.pcap -q -z conv,ip
   ```
2. **Ekstraksi File Otomatis dari Traffic HTTP / SMB / TFTP**:
   ```bash
   mkdir -p ./exported_files
   tshark -r capture.pcap --export-objects http,./exported_files/
   tshark -r capture.pcap --export-objects smb,./exported_files/
   tshark -r capture.pcap --export-objects tftp,./exported_files/
   ```
3. **Analisis DNS Tunneling / Exfiltration**:
   ```bash
   tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name | sort | uniq -c | sort -nr
   ```
4. **Analisis Kredensial & Cleartext (FTP, HTTP POST, Telnet)**:
   ```bash
   tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e ip.src -e ip.dst -e http.file_data
   tshark -r capture.pcap -Y "ftp.request.command == PASS || ftp.request.command == USER" -T fields -e ftp.request.arg
   ```
5. **Follow TCP Stream & Payload Extraction**:
   ```bash
   tshark -r capture.pcap -z follow,tcp,ascii,0
   ```

---

##  CHECKLIST PERSENJATAAN DI WSL (`/usr/local/bin` & `/usr/bin`)

| Kategori | Tool Tersedia di WSL | Status |
| :--- | :--- | :---: |
| **Disk & File System** | `ewfmount`, `fls`, `icat`, `mmls`, `fsstat`, `analyzeMFT`, `rifiuti2`, `pylnk3`, `dissect` |  **Ready** |
| **Windows Event Logs**| `hayabusa`, `chainsaw`, `evtx_dump`, `python-evtx` |  **Ready** |
| **Registry** | `python-registry`, `hivex`, `regipy` |  **Ready** |
| **Memory Dump** | `vol` (Volatility 3), `yara`, `bulk_extractor`, `strings` |  **Ready** |
| **Binary & Firmware** | `binwalk`, `foremost`, `scalpel`, `r2`, `gdb`, `pefile`, `capstone`, `jadx`, `oletools` |  **Ready** |
| **Stego & Audio** | `zsteg`, `stegseek`, `steghide`, `exiftool`, `pngcheck`, `sox` |  **Ready** |
| **Network & PCAP** | `tshark`, `tcpdump`, `scapy`, `dpkt` |  **Ready** |
| **Wordlists & Crack** | `john`, `hashcat`, `7z`, `/usr/share/wordlists/rockyou.txt` (134 MB) |  **Ready** |
| **CLI Renderer** | `glow` |  **Ready** |

---

###  CARA RENDER / BACA DOKUMEN INI DI TERMINAL WSL:
```bash
glow /mnt/d/tools/md/notesall.md
# Atau dengan mode pager per halaman:
glow -p /mnt/d/tools/md/notesall.md
```
