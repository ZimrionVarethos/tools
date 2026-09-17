#!/usr/bin/env bash
# Script to install / extract rockyou.txt in WSL / Linux
set -e

WORDLIST_DIR="/usr/share/wordlists"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Setting up rockyou.txt wordlist..."

if [ -f "$WORDLIST_DIR/rockyou.txt" ]; then
    echo "[] rockyou.txt already exists in $WORDLIST_DIR/rockyou.txt"
    exit 0
fi

if [ -f "$WORDLIST_DIR/rockyou.txt.gz" ]; then
    echo "[*] Decompressing $WORDLIST_DIR/rockyou.txt.gz..."
    sudo gunzip -k "$WORDLIST_DIR/rockyou.txt.gz"
    echo "[] Extracted to $WORDLIST_DIR/rockyou.txt"
    exit 0
fi

# If wordlists directory does not exist, install seclists or download rockyou
echo "[*] Installing wordlists package..."
sudo apt-get update -y && sudo apt-get install -y wordlists seclists || true

if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
    echo "[] Installed and extracted to /usr/share/wordlists/rockyou.txt"
elif [ -f "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" ]; then
    sudo tar -xzf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /usr/share/wordlists/
    echo "[] Installed to /usr/share/wordlists/rockyou.txt"
else
    echo "[*] Downloading rockyou.txt directly from github repository..."
    sudo mkdir -p /usr/share/wordlists
    sudo curl -L "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" -o /usr/share/wordlists/rockyou.txt
    echo "[] Downloaded to /usr/share/wordlists/rockyou.txt"
fi
