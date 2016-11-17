#!/bin/bash

file1=$1
file2=$2
cmp -l $file1 $file2 | gawk '{printf "%08X %02X %02X\n", $1, strtonum(0$2), strtonum(0$3)}'
