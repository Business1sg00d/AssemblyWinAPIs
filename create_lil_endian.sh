#!/bin/bash

# Check for input
if [ -z "$1" ]; then
    echo "Usage: $0 \"string\""
    exit 1
fi

input="$1"

# Convert string to hex
hex=$(echo -n "$input" | xxd -p)

# Split into bytes (two hex chars per byte) and reverse for little endian
# Group into 4-byte (8 hex chars) chunks for typical little-endian word output
echo "Original hex: $hex"
echo -n "Little-endian: "

# Pad hex to multiple of 8 chars (optional, for 4-byte words)
len=${#hex}
pad=$((8 - len % 8))
if [ $pad -lt 8 ]; then
    hex="${hex}$(printf '0%.0s' $(seq 1 $pad))"
fi

# Reverse each 4-byte chunk
for ((i=0; i<${#hex}; i+=8)); do
    chunk=${hex:i:8}
    # Reverse bytes
    echo -n "$(echo $chunk | sed 's/../& /g' | awk '{for(i=NF;i>0;i--)printf $i"";print ""}') "
done

echo
