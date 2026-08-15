#!/usr/bin/env bash
# GhostBuster — one-shot installer
# Handles Kali/Debian PEP 668, Termux, and plain Linux/macOS.

set -e

_G="\033[38;5;46m"; _O="\033[38;5;208m"; _R="\033[0m"; _D="\033[38;5;240m"

echo -e "${_O}👻 GhostBuster installer${_R}"
echo -e "${_D}────────────────────────${_R}"

# Detect environment
IS_KALI=0; IS_TERMUX=0
[ -f /etc/os-release ] && grep -qi "kali\|debian\|ubuntu" /etc/os-release && IS_KALI=1
[ -n "$TERMUX_VERSION" ] || [ -d "$PREFIX/etc" ] && IS_TERMUX=1

# Prefer apt for the big binary wheels on Kali/Debian
if [ "$IS_KALI" = "1" ] && [ "$IS_TERMUX" = "0" ]; then
  echo -e "${_G}[+]${_R} Kali/Debian detected — installing system packages via apt"
  sudo apt update -qq
  sudo apt install -y --no-install-recommends \
      python3-aiohttp python3-phonenumbers python3-exifread \
      python3-networkx python3-matplotlib python3-yaml || true
fi

# Fill any gaps with pip (--break-system-packages allowed on Kali)
PIP_ARGS=""
if python3 -m pip install --help 2>&1 | grep -q "break-system-packages"; then
  PIP_ARGS="--break-system-packages"
fi

echo -e "${_G}[+]${_R} Installing remaining Python deps via pip ${PIP_ARGS}"
python3 -m pip install --user $PIP_ARGS -r requirements.txt

echo ""
echo -e "${_G}✔ Install complete!${_R}"
echo -e "${_D}Try:${_R} ${_O}python3 ghostbuster.py investigate ip 1.1.1.1${_R}"
