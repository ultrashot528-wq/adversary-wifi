#!/bin/bash

set -e

SCRIPT_NAME="adversary_wifi.py"
TARGET_BIN="/usr/local/bin/adversary"

read -r -n 1 -p "Press ANY KEY to continue..." </dev/tty
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "Error: Run as root (sudo)."
  exit 1
fi

if [ ! -f "$SCRIPT_NAME" ]; then
  echo "Error: $SCRIPT_NAME not found."
  exit 1
fi

for i in {1..10}; do
  if apt-get update -y 2>/dev/null; then
    break
  fi
  if [ "$i" -eq 10 ]; then
    echo "Error: apt database locked."
    exit 1
  fi
  sleep 3
done

for i in {1..5}; do
  if apt-get install -y tcpdump libpcap-dev python3-pip python3-dev; then
    break
  fi
  if [ "$i" -eq 5 ]; then
    echo "Error: apt install failed."
    exit 1
  fi
  sleep 3
done

python3 -m pip install pyfiglet scapy --break-system-packages

if ! grep -q "^#!/usr/bin/env python3" "$SCRIPT_NAME"; then
    sed -i '1i#!/usr/bin/env python3' "$SCRIPT_NAME"
fi

mkdir -p "$(dirname "$TARGET_BIN")"
cp "$SCRIPT_NAME" "$TARGET_BIN"
chmod 755 "$TARGET_BIN"

echo "Setup complete. Run using: sudo adversary"

