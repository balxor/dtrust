#!/bin/bash
# Setup script for Format String Lab Environment
# Run on Ubuntu/Debian or WSL2

set -e

echo "=== Format String Lab Setup ==="
echo

# Check dependencies
echo "[*] Checking dependencies..."

MISSING=""

command -v gcc >/dev/null 2>&1 || MISSING="$MISSING gcc"
command -v gdb >/dev/null 2>&1 || MISSING="$MISSING gdb"
command -v python3 >/dev/null 2>&1 || MISSING="$MISSING python3"
dpkg -l | grep -q gcc-multilib || MISSING="$MISSING gcc-multilib"

if [ -n "$MISSING" ]; then
    echo "[!] Missing packages:$MISSING"
    echo "[*] Installing..."
    sudo apt update
    sudo apt install -y gcc gcc-multilib gdb python3 python3-pip
else
    echo "[+] All system dependencies satisfied"
fi

# Install pwntools
echo "[*] Installing pwntools..."
python3 -m pip install --user pwntools 2>/dev/null || pip3 install pwntools

# Compile all labs
echo "[*] Compiling lab binaries..."
make clean 2>/dev/null
make all

echo
echo "[+] Setup complete!"
echo
echo "Lab binaries compiled:"
echo "  ./level0/format0 - Stack Leak"
echo "  ./level1/format1 - Arbitrary Read"
echo "  ./level2/format2 - Basic Write (%n)"
echo "  ./level3/format3 - Precise Write (%hn)"
echo "  ./level4/format4 - Full Chain (GOT Overwrite)"
echo
echo "Run exploits:"
echo "  python3 level0/exploit0.py"
echo "  python3 level1/exploit1.py"
echo "  python3 level2/exploit2.py"
echo "  python3 level3/exploit3.py"
echo "  python3 level4/exploit4.py"
echo
echo "Check protections:"
echo "  python3 helpers.py ./level4/format4"
echo
echo "Manual testing:"
echo "  echo 'AAAA%p.%p.%p.%p.%p.%p.%p' | ./level0/format0"
