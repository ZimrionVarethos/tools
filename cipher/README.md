# Universal Cryptography & Obfuscation Analysis Toolkit (`cipher/`)

Platform analisis, pendeteksi jenis cipher/enkripsi, dan kalkulator deobfuscation otomatis berbasis **Pure Python**. Dilengkapi dengan engine diagnostik pintar **`ciphercheck`** dan template script praktis siap pakai untuk memecahkan berbagai tantangan kriptografi CTF & DFIR.

---

##  Daftar Isi
1. [Fitur Utama `ciphercheck`](#1-fitur-utama-ciphercheck)
2. [Cara Menjalankan `ciphercheck`](#2-cara-menjalankan-ciphercheck)
   - [Mode Interaktif (Terminal Prompt)](#a-mode-interaktif-terminal-prompt)
   - [Mode File / Command Line Direct](#b-mode-file--command-line-direct)
3. [Cryptographic Key & Nonce Harvester (`cryptohunt`)](#3-cryptographic-key--nonce-harvester-cryptohunt)
4. [ Cheatsheet: Cara Mengenali Jenis Cipher Tanpa Menghafal](#4--cheatsheet-cara-mengenali-jenis-cipher-tanpa-menghafal)
5. [ Daftar Template Script Siap Pakai (`T_*.py`)](#5--daftar-template-script-siap-pakai-t_py)
   - [T_aes.py (AES-128/192/256: ECB, CBC, CTR, GCM)](#a-t_aespy-aes-master)
   - [T_xor.py (Single-Byte, Repeating & Rolling XOR)](#b-t_xorpy-xor-master)
   - [T_rc4.py (RC4 / ARC4 Stream Cipher)](#c-t_rc4py-rc4-stream-cipher)
   - [T_rsa.py (RSA: Wiener, Fermat, Factoring)](#d-t_rsapy-rsa-asymmetric-toolkit)
   - [T_chacha20.py (ChaCha20 & Poly1305)](#e-t_chacha20py-chacha20--poly1305)
   - [T_classical.py (Caesar, Vigenere, Atbash, Railfence)](#f-t_classicalpy-classical-ciphers)

---

## 1. Fitur Utama `ciphercheck`

| Modul Analisis | Deskripsi Kemampuan |
| :--- | :--- |
| ** Multi-Encoding Detector** | Mendeteksi otomatis teks Base64, Base32, Base58, Base85, Hex/Base16, Binary ASCII (`0101...`), Decimal ASCII (`102 108 97...`), URL-encoding, dan HTML entities. |
| ** Shannon Entropy Profiling** | Menghitung entropi data (skala 0.0 - 8.0) untuk menentukan apakah data berupa Plaintext (< 4.5), Obfuscated (4.5 - 6.5), atau Terenkripsi/Terkonpresi (> 7.2). |
| ** Cipher Classifier** | Mengidentifikasi kandidat cipher berdasarkan keselarasan blok data (*Block Alignment* 16-byte untuk AES, 8-byte untuk DES/3DES, atau Arbitrary untuk AES-CTR/ChaCha20/RC4). |
| ** Auto-XOR Hunter** | Otomatis melakukan *brute-force* seluruh 256 kunci Single-byte XOR dan mendeteksi flag CTF (`flag{`, `CTF{`, `http://`, `MZ`, dll.). |
| ** Magic Signature Scanner** | Memeriksa apakah setelah didecode/di-XOR data menghasilkan file biner asli (PE `.exe`, ELF, PNG, GZIP, ZIP, PDF). |
| ** Hash Identifier** | Mengenali signature hash MD5, SHA-1, SHA-256, SHA-512, bcrypt, NTLM, dan Unix crypt. |

---

## 2. Cara Menjalankan `ciphercheck`

### A. Mode Interaktif (Terminal Prompt)
Cukup ketik `ciphercheck` tanpa argumen, lo bisa langsung paste teks cipher atau path file:
```bash
ciphercheck
```
* Muncul prompt interaktif: Masukkan ciphertext string, hex, base64, atau file path.

### B. Mode File / Command Line Direct
```bash
# Analisis file ciphertext:
ciphercheck -i cipher.txt

# Analisis string langsung dari terminal:
ciphercheck -t "ZGNSdmFXVCJYVAFvYj2Pvf24Ac72V8EHi2Rl3BgtGYk="

# Uji coba dekripsi dengan kunci tertentu:
ciphercheck -i payload.bin -k "ZjLtHquGbCxfsnoS"
```

---

## 3. Cryptographic Key & Nonce Harvester (`cryptohunt`)

Engine analisis biner & memori untuk memanen kandidat kunci kriptografi (Key 32B/16B, Nonce 12B/8B), mengenali konstanta algoritma standar (ChaCha20 sigma/tau, AES S-Boxes, SHA constants), mengidentifikasi pasangan struct `{Nonce, Key}`, serta melakukan uji dekripsi otomatis terhadap ciphertext target.

### Syntax Lengkap:
```bash
cryptohunt <file_biner|file_memori> [opsi]
```

### Opsi yang Tersedia:
- `--pair` : Auto-detect dan ekstraksi pasangan struct kriptografi `{Nonce, Key}`.
- `--test-decrypt <CIPHERTEXT>` : String ciphertext (Base64 atau Hex) untuk diuji coba langsung terhadap kandidat kunci hasil panen.
- `--prefix "<PREFIX>"` : Prefix plaintext yang diharapkan (misal `CTF{`, `FLAG{`, `http://`).
- `--near "<TARGET>"` : Fokuskan pencarian di sekitar alamat offset hex (`0xc100`) atau string anchor (`flag.txt`, `expand 32-byte k`).
- `--range <BYTES>` : Radius pencarian di sekitar target saat menggunakan `--near` (default: 64KB).
- `--size <LIST>` : Ukuran kandidat byte yang dipanen (default: `32,16,12,8`).
- `--json <file.json>` : Ekspor hasil panen ke format JSON.

### Contoh Penggunaan:
```bash
# 1. Pindai biner ELF & auto-detect pasangan {Nonce, Key}:
cryptohunt malware.elf --pair

# 2. Panen kunci & auto-test dekripsi payload terenkripsi:
cryptohunt malware.elf --pair --test-decrypt "KEVt/ztn..." --prefix "FLAG{"

# 3. Targeted key hunting pada memory dump di sekitar konstanta ChaCha20:
cryptohunt memory.lime --near "expand 32-byte k" --range 65536
```

---

## 4.  Cheatsheet: Cara Mengenali Jenis Cipher Tanpa Menghafal

Gunakan rumus eliminasi cepat ini saat menganalisis artefak terenkripsi:

### 1. Dari Panjang Kunci (Key Length):
* **16 Karakter / 16 Byte (128-bit):** $\rightarrow$ **AES-128** (atau RC4).
* **24 Karakter / 24 Byte (192-bit):** $\rightarrow$ **AES-192** atau **3DES**.
* **32 Karakter / 32 Byte (256-bit):** $\rightarrow$ **AES-256** atau **ChaCha20**.

### 2. Dari Ukuran Ciphertext (Data Output):
* **Selalu Pas Kelipatan 16 Byte (16, 32, 48, 64...):**
  $\rightarrow$ **AES-ECB** (tanpa IV) atau **AES-CBC** (dengan 16-byte IV di awal).
* **Ukuran Bebas / Ganjil (49B, 73B, 121B, dll.) dengan Entropi Tinggi (> 7.2):**
  $\rightarrow$ **AES-CTR**, **ChaCha20**, atau **RC4** (Stream Ciphers).
* **Selalu Pas Kelipatan 8 Byte:** $\rightarrow$ **DES / 3DES / Blowfish**.

### 3. Dari Ciri Khas Header / Nonce:
* Jika **16 byte pertama selalu berubah acak** di setiap request $\rightarrow$ **IV (Initialization Vector) AES**.
* Jika **8 / 12 byte pertama acak** $\rightarrow$ **Nonce ChaCha20**.

---

## 5.  Daftar Template Script Siap Pakai (`T_*.py`)

Setiap template dirancang agar bisa lo jalankan langsung via CLI tanpa perlu coding ulang dari nol:

---

### A. `T_aes.py` (AES Master)
Mendukung mode: **`ECB`**, **`CBC`**, **`CTR`**, **`GCM`**, **`CFB`**, **`OFB`**.

```bash
# Dekripsi AES-CTR dengan auto-extract 16-byte IV di awal payload:
python3 /mnt/d/tools/cipher/T_aes.py -k "ZjLtHquGbCxfsnoS" -i payload.b64 -m CTR

# Dekripsi AES-CBC dengan custom IV hex:
python3 /mnt/d/tools/cipher/T_aes.py -k "MySecretKey12345" -i cipher.bin -m CBC --iv "000102030405060708090a0b0c0d0e0f"

# Dekripsi AES-ECB (tanpa IV):
python3 /mnt/d/tools/cipher/T_aes.py -k "MySecretKey12345" -i cipher.hex -m ECB
```

---

### B. `T_xor.py` (XOR Master)
Mendukung: **Single-byte brute force**, **Repeating key**, dan **Rolling seed**.

```bash
# Brute force seluruh 256 Single-Byte XOR keys:
python3 /mnt/d/tools/cipher/T_xor.py -i obfuscated.txt --brute

# Repeating XOR dengan string key:
python3 /mnt/d/tools/cipher/T_xor.py -i payload.bin -k "MYSECRETKEY"

# Rolling/Incremental 4-byte XOR (khas malware / NimPlant):
python3 /mnt/d/tools/cipher/T_xor.py -i payload.bin -k 0x3386dd90 --rolling
```

---

### C. `T_rc4.py` (RC4 Stream Cipher)

```bash
# Dekripsi payload RC4 dengan kunci teks:
python3 /mnt/d/tools/cipher/T_rc4.py -k "xobvrE_x11mb" -i encrypted_shellcode.bin -o decrypted.bin
```

---

### D. `T_rsa.py` (RSA Asymmetric Toolkit)
Mendukung: **Wiener's Attack (small d)**, **Fermat Factorization**, dan kalkulasi $(p, q, e)$.

```bash
# Dekripsi standar dengan p, q, e, c:
python3 /mnt/d/tools/cipher/T_rsa.py -p <prime_p> -q <prime_q> -e 65537 -c <ciphertext>

# Jalankan Wiener's attack (jika d kecil):
python3 /mnt/d/tools/cipher/T_rsa.py -n <modulus_n> -e <exponent_e> -c <ciphertext> --wiener

# Jalankan Fermat Factorization (jika p dan q berdekatan):
python3 /mnt/d/tools/cipher/T_rsa.py -n <modulus_n> -e 65537 -c <ciphertext> --fermat
```

---

### E. `T_chacha20.py` (ChaCha20 & Poly1305)

```bash
# Dekripsi ChaCha20 dengan 32-byte key:
python3 /mnt/d/tools/cipher/T_chacha20.py -k "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" -i data.b64
```

---

### F. `T_classical.py` (Classical Ciphers)
Mendukung: **Caesar ROT-1 s/d ROT-25**, **Vigenere**, **Atbash**, **Rail Fence**.

```bash
# Brute-force seluruh 25 kemungkinan Caesar ROT:
python3 /mnt/d/tools/cipher/T_classical.py -t "Ebg13 grkg" --caesar

# Selesaikan Vigenere dengan kata kunci:
python3 /mnt/d/tools/cipher/T_classical.py -t "Lxfopvefrnhr" --vigenere "LEMON"

# Selesaikan Rail Fence dengan N rel:
python3 /mnt/d/tools/cipher/T_classical.py -t "WECRLTEERDSOEEFEAOCAIVDEN" --railfence 3
```

---

##  Setup & Alias Global

Jalankan perintah ini sekali untuk mengaktifkan shortcut `ciphercheck`:
```bash
bash /mnt/d/tools/install_alias.sh
source ~/.bashrc
```
