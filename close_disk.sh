#!/bin/bash -xv
WDIR=temp

set -e
SESSION=$1
DISK=$2
DISK_NUM=`cat /sys/fs/vdisk/$SESSION/$DISK/number`
umount /dev/vdisk$DISK_NUM || true
cat /sys/fs/vdisk/$SESSION/$DISK/disk_id
echo $DISK > /sys/fs/vdisk/$SESSION/close_disk
