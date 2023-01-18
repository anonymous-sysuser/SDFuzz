#!/bin/bash
for filename in ./fuzz/mjs-issues-78/obj-aflgo/temp/dot-files/cfg.*.dot; do
  echo "$filename"
  python3 distance.py \
  -d "$filename"\
  -o "$(basename "$filename" .dot)_temp_cg.txt1" \
  -n ./fuzz/mjs-issues-78/obj-aflgo/temp/BBnames.txt\
  -s ./fuzz/mjs-issues-78/obj-aflgo/temp/BBcalls.txt
done

