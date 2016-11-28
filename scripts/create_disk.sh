#!/bin/bash -xv
set -e

WDIR=temp
SESSION=$1
DISK=$2
SPACE=$3

cat /sys/fs/vdisk/$SESSION/session_id
KEY=`echo 1q2w3e | sha256sum | awk '{ print $1 }'`
echo $DISK $SPACE $KEY > /sys/fs/vdisk/$SESSION/create_disk
DISK_NUM=`cat /sys/fs/vdisk/$SESSION/$DISK/number`
cat /sys/fs/vdisk/$SESSION/$DISK/disk_id
cat /sys/fs/vdisk/$SESSION/$DISK/size
cat /sys/fs/vdisk/$SESSION/$DISK/disk_handle

DEV=/dev/vdisk$DISK_NUM
MNT=/mnt/vdisk$DISK_NUM
dd if=/dev/urandom of=$WDIR/file-$DISK_NUM bs=1M count=16
dd if=$WDIR/file-$DISK_NUM of=$DEV bs=1M count=16
dd if=$DEV of=$WDIR/file2-$DISK_NUM bs=1M count=16

md5sum $WDIR/file-$DISK_NUM $WDIR/file2-$DISK_NUM

umount $MNT || true
rm -rf $MNT
mkdir $MNT
mkfs.ext4 $DEV
mount -t ext4 $DEV $MNT
