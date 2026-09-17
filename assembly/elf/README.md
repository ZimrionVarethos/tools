#  Linux ELF Binary Doctor & Inspector (`assembly/elf/`)

Alat diagnostik dan inspeksi biner Linux executable (**ELF32 / ELF64**):
- **`elfdoctor`** / **`elffix`** : Inspeksi header `\x7fELF`, arsitektur CPU (x86, x64, ARM, MIPS), Endianness, entry point, status simbol (*Stripped* vs *Non-Stripped*), dan deteksi UPX packing.

---

##  Syntax & Contoh Perintah

```bash
# Diagnosa file binary Linux ELF:
elfdoctor linux_malware
elfdoctor /bin/ls
```
