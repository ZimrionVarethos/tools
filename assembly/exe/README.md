#  Windows PE Binary Doctor & Fixer (`assembly/exe/`)

Suite diagnostik dan perbaikan biner executable Windows (**`.exe`**, **`.dll`**, **`.sys`**) berbasis Pure Python:
- **`exefix`** : Perbaikan alignment section memori hasil dump WinDbg/Volatility.
- **`exedoctor`** : Inspeksi integritas header PE dan deteksi kerusakan biner.
- **`ghidraguide`** : Generator roadmap dan peta navigasi Ghidra otomatis.

---

##  Syntax & Contoh Perintah

```bash
# 1. Diagnosa kerusakan biner PE / memory dump:
exedoctor DbgInfo.exe

# 2. Realign memory dump agar Ghidra tidak error:
exefix DbgInfo_dumped.exe -o ./DbgInfo_fixed.exe

# 3. Carve PE dari polyglot / shellcode wrapper & potong overlay:
exefix malware.bin --carve --strip-overlay -o ./clean.exe

# 4. Generate peta navigasi Ghidra & Writeup blueprint:
ghidraguide rev.exe
```
