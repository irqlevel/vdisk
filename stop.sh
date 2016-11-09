#!/bin/bash -xv

WDIR=temp

echo 0 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace > $WDIR/trace
echo '' > /sys/kernel/debug/tracing/trace
echo 0 > /sys/kernel/debug/tracing/events/vdisk/enable

rmmod vdisk-mod
