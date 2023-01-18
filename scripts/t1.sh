#!/bin/bash
python3 cg.py \
-o ./cg-distance.txt \
-c ./temp-out-cg-distance.txt \
-f ./fuzz/mjs-issues-78/obj-aflgo/temp/Ftargets.txt \
-d ./fuzz/mjs-issues-78/obj-aflgo/temp/dot-files/callgraph.dot

for filename in ./fuzz/mjs-issues-78/obj-aflgo/temp/dot-files/cfg.*.dot; do
  echo "$filename"
  python3 distance.py \
  -d "$filename"\
  -o ./cfg-distance.txt \
  -c ./cg-distance.txt \
  -t ./fuzz/mjs-issues-78/obj-aflgo/temp/BBtargets.txt\
  -n ./fuzz/mjs-issues-78/obj-aflgo/temp/BBnames.txt\
  -s ./fuzz/mjs-issues-78/obj-aflgo/temp/BBcalls.txt\
  -f ./fuzz/mjs-issues-78/obj-aflgo/temp/Ftargets.txt
done
