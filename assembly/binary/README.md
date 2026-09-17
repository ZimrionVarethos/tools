#  Raw Binary & Shellcode Disassembler (`assembly/binary/`)

Alat disassembler biner mentah, shellcode payload, dan firmware blobs:
- **`disasm`** / **`shellcode`** / **`blobscan`** :
  - Support multi-arsitektur: **x64, x86, ARM, ARM64**.
  - Deteksi pola serangan shellcode: **PEB Walking** (`gs:[0x60]` / `fs:[0x30]`), **NOP Sleds** (`\x90`), **ROR13 API Hashing**, dan **Metasploit/Cobalt Strike Stagers**.
  - Ekstraksi string terbaca & endpoint C2 di dalam shellcode.

---

##  Syntax & Contoh Perintah

```bash
# 1. Disassemble shellcode x64 (default):
disasm shellcode.bin

# 2. Disassemble shellcode 32-bit (x86) dengan custom base address:
disasm shellcode32.bin -a x86 -b 0x1000 -n 50

# 3. Disassemble shellcode ARM64:
disasm payload_arm64.bin -a arm64
```
