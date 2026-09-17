#!/usr/bin/env bash
# Script to register DFIR tools aliases in ~/.bashrc for WSL / Linux

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
BASHRC="$HOME/.bashrc"

echo "=== Setting up DFIR Tools for WSL / Linux ==="
echo "Tools Directory: $TOOLS_DIR"

# Ensure execute permissions
chmod +x "$TOOLS_DIR/tools" "$TOOLS_DIR/tools.py" 2>/dev/null

# Ensure PATH is set at the top of ~/.bashrc so non-interactive shells also have it
if ! grep -q "/mnt/d/tools/bin" "$BASHRC" 2>/dev/null; then
    sed -i '1i export PATH="/mnt/d/tools/bin:/mnt/d/tools:$PATH"' "$BASHRC"
fi

# Remove existing block if any and update with all aliases
if grep -q "DFIR Tools Aliases" "$BASHRC" 2>/dev/null; then
    sed -i '/# --- DFIR Tools Aliases ---/,/# --------------------------/d' "$BASHRC"
fi

cat << 'EOF' >> "$BASHRC"

# --- DFIR Tools Aliases ---
alias limescan="python3 /mnt/d/tools/lime/scanner.py"
alias limebuild="python3 /mnt/d/tools/lime/builder.py"
alias limefast="python3 /mnt/d/tools/lime/fast.py"
export PATH="/mnt/d/tools/bin:/mnt/d/tools:$PATH"
alias tools="python3 /mnt/d/tools/tools.py"
alias globalscan="python3 /mnt/d/tools/core/globalscan.py"
alias gscan="python3 /mnt/d/tools/core/globalscan.py"
alias globalscan2="/mnt/d/tools/bin/globalscan2"
alias gscan2="/mnt/d/tools/bin/globalscan2"
alias strings2="/mnt/d/tools/bin/strings2"
alias binwalk2="/mnt/d/tools/bin/binwalk2"

# Top-Level Module Routing & Help Shortcuts
alias pcap="python3 /mnt/d/tools/tools.py pcap"
alias dmp="python3 /mnt/d/tools/tools.py dmp"
alias ad1="python3 /mnt/d/tools/tools.py ad1"
alias stego="python3 /mnt/d/tools/tools.py stego"
alias steg="python3 /mnt/d/tools/tools.py stego"
alias assembly="python3 /mnt/d/tools/tools.py assembly"
alias exe="python3 /mnt/d/tools/tools.py exe"
alias elf="python3 /mnt/d/tools/tools.py elf"

# PCAP Network Forensics
alias pcapfirst="python3 /mnt/d/tools/pcap/first_look.py"
alias pcaptree="python3 /mnt/d/tools/pcap/tree.py"
alias pcapfile="python3 /mnt/d/tools/pcap/file_carver.py"
alias pcapstream="python3 /mnt/d/tools/pcap/stream_follower.py"
alias pcapcat="python3 /mnt/d/tools/pcap/stream_follower.py"
alias pcapscan="python3 /mnt/d/tools/pcap/scanner.py"
alias pcapscanstream="python3 /mnt/d/tools/pcap/scan_stream.py"
alias pcappayload="python3 /mnt/d/tools/pcap/payload_extractor.py"
alias pcappld="python3 /mnt/d/tools/pcap/payload_extractor.py"
alias pcapportpayload="python3 /mnt/d/tools/pcap/port_payload.py"
alias pcapport="python3 /mnt/d/tools/pcap/port_payload.py"
alias pcapendpoint="python3 /mnt/d/tools/pcap/endpoint.py"
alias pcapend="python3 /mnt/d/tools/pcap/endpoint.py"
alias pcapurl="python3 /mnt/d/tools/pcap/endpoint.py"
alias pcapurls="python3 /mnt/d/tools/pcap/endpoint.py"

# Windows & Linux / Android Raw Memory Dump Forensics
alias volrust="/mnt/d/tools/bin/vol-rs"
alias memcarve="/mnt/d/tools/bin/memcarve"
alias dmpscan="python3 /mnt/d/tools/dmp/scanner.py"
alias dmpdump="python3 /mnt/d/tools/dmp/dumper.py"
alias dmppeb="python3 /mnt/d/tools/dmp/scanner.py --peb"
alias dmpmodules="python3 /mnt/d/tools/dmp/scanner.py --modules"
alias dmpflags="python3 /mnt/d/tools/dmp/scanner.py --flags-only"

# Assembly & Reverse Engineering Suite (assembly/)
# 1. Ghidra Interactive Live Companion
alias ghidraanalyze="python3 /mnt/d/tools/assembly/ghidra/analyzer.py"
alias ghidracli="python3 /mnt/d/tools/assembly/ghidra/analyzer.py"
alias ghidrabridge="python3 /mnt/d/tools/assembly/ghidra/analyzer.py"

# 2. Windows PE Binary Doctor & Fixer
alias exefix="python3 /mnt/d/tools/assembly/exe/fixer.py"
alias exedoctor="python3 /mnt/d/tools/assembly/exe/fixer.py --diagnose"
alias exefixed="python3 /mnt/d/tools/assembly/exe/fixer.py"
alias ghidraguide="python3 /mnt/d/tools/assembly/exe/ghidraguide.py"
alias wuguide="python3 /mnt/d/tools/assembly/exe/ghidraguide.py"

# 3. Linux ELF Binary Doctor
alias elffix="python3 /mnt/d/tools/assembly/elf/inspector.py"
alias elfdoctor="python3 /mnt/d/tools/assembly/elf/inspector.py"
alias elfinspect="python3 /mnt/d/tools/assembly/elf/inspector.py"

# 4. Multi-Arch Raw Shellcode Disassembler
alias disasm="python3 /mnt/d/tools/assembly/binary/disasm.py"
alias shellcode="python3 /mnt/d/tools/assembly/binary/disasm.py"
alias blobscan="python3 /mnt/d/tools/assembly/binary/disasm.py"

# Steganography & Artifact Triage Suite (stego/)
alias stegoscan="python3 /mnt/d/tools/stego/scanner.py"
alias stegscan="python3 /mnt/d/tools/stego/scanner.py"
alias stegodiff="python3 /mnt/d/tools/stego/differ.py"
alias stegdiff="python3 /mnt/d/tools/stego/differ.py"
alias stegocrack="python3 /mnt/d/tools/stego/cracker.py"
alias stegcrack="python3 /mnt/d/tools/stego/cracker.py"
alias stegoaudio="python3 /mnt/d/tools/stego/audio.py"
alias stegaudio="python3 /mnt/d/tools/stego/audio.py"

# Cryptography & Obfuscation Analysis
alias ciphercheck="python3 /mnt/d/tools/cipher/checker.py"
alias cipher="python3 /mnt/d/tools/cipher/checker.py"
alias cryptohunt="python3 /mnt/d/tools/cipher/cryptohunt.py"
alias keyhunt="python3 /mnt/d/tools/cipher/cryptohunt.py"
alias keyfind="python3 /mnt/d/tools/cipher/cryptohunt.py"
alias cryptoparse="python3 /mnt/d/tools/cipher/cryptohunt.py"

# AccessData AD1 Forensics
alias ad1history="python3 /mnt/d/tools/ad1/history.py"
alias ad1amcache="python3 /mnt/d/tools/ad1/amcache.py"
alias ad1NTUSER="python3 /mnt/d/tools/ad1/ntuser.py"
alias ad1ntuser="python3 /mnt/d/tools/ad1/ntuser.py"
alias ad1recent="python3 /mnt/d/tools/ad1/recent.py"
alias ad1extensions="python3 /mnt/d/tools/ad1/extensions.py"
alias ad1extension="python3 /mnt/d/tools/ad1/extensions.py"
alias ad1scan="python3 /mnt/d/tools/ad1/scan.py"
alias ad1scandetail="python3 /mnt/d/tools/ad1/scandetail.py"
alias ad1detail="python3 /mnt/d/tools/ad1/scandetail.py"
alias ad1dpapi="python3 /mnt/d/tools/ad1/dpapi_decrypt.py"
alias ad1decrypt="python3 /mnt/d/tools/ad1/dpapi_decrypt.py"
alias ad1cli="python3 /mnt/d/tools/ad1/cli.py"
# --------------------------
EOF

echo "[] Aliases registered in ~/.bashrc"
echo "[i] Run 'source ~/.bashrc' or open a new WSL terminal to activate."
echo "=== Setup Completed! ==="
