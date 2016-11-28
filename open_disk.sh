#!/bin/bash -xv
WDIR=temp

set -e

SESSION=$1
DISK=$2

cat /sys/fs/vdisk/$SESSION/session_id
KEY=`echo 1q2w3e | sha256sum | awk '{ print $1 }'`
echo $DISK $KEY > /sys/fs/vdisk/$SESSION/open_disk
cat /sys/fs/vdisk/$SESSION/$DISK/disk_id
cat /sys/fs/vdisk/$SESSION/$DISK/size
cat /sys/fs/vdisk/$SESSION/$DISK/disk_handle

DISK_NUM=`cat /sys/fs/vdisk/$SESSION/$DISK/number`
DEV=/dev/vdisk$DISK_NUM
MNT=/mnt/vdisk$DISK_NUM
umount $MNT || true
rm -rf $MNT || true
mkdir $MNT
mount -t ext4 $DEV $MNT
