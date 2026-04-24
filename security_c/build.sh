#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SecureAuth — C Module Build Script
#  Compiles validation.c into a shared library (libsecurity.so)
# ═══════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/validation.c"
OUT="$SCRIPT_DIR/libsecurity.so"

echo "╔══════════════════════════════════════════╗"
echo "║   SecureAuth C Engine — Build Script     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "[*] Source : $SRC"
echo "[*] Output : $OUT"
echo ""

if ! command -v gcc &> /dev/null; then
    echo "[✗] GCC not found. Please install GCC:"
    echo "    macOS: xcode-select --install"
    echo "    Linux: sudo apt install gcc"
    exit 1
fi

echo "[*] Compiling with GCC (O2 optimization)..."
gcc -shared -fPIC -O2 -Wall \
    -o "$OUT" \
    "$SRC"

echo ""
echo "[✓] Build successful!"
echo "[✓] Library: $OUT"
echo ""
echo "Flask will auto-load this library on next startup."
