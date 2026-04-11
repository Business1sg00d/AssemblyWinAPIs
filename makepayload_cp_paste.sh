#!/bin/bash

file="$1"

if [ -z "$file" ] || [ ! -f "$file" ]; then
    echo "Usage: $0 <shellcode_file>"
    exit 1
fi

# Read file content
input=$(cat "$file")

# Remove whitespace and newlines
input=$(echo "$input" | tr -d ' \n\r')

IFS=',' read -ra bytes <<< "$input"

count=${#bytes[@]}

addr_reg="rax"
offset=0

for ((i=0; i<count; i+=4)); do
    b0=${bytes[i]}
    b1=${bytes[i+1]:-0x00}
    b2=${bytes[i+2]:-0x00}
    b3=${bytes[i+3]:-0x00}

    val=$(printf "%02x%02x%02x%02x" \
        $((16#${b3#0x})) \
        $((16#${b2#0x})) \
        $((16#${b1#0x})) \
        $((16#${b0#0x})))

    echo "mov dword ptr [${addr_reg}+${offset}], 0x${val}"

    offset=$((offset + 4))
done
