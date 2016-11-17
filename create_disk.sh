#!/bin/bash -xv
set -e

WDIR=temp

echo 1 > /sys/fs/vdisk/create_session
echo 104.199.86.71:9111 > /sys/fs/vdisk/session1/connect
#echo 127.0.0.1:9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q2w3e > /sys/fs/vdisk/session1/login

cat /sys/fs/vdisk/session1/session_id
KEY=`echo 1q2w3e | sha256sum | awk '{ print $1 }'`
echo 1 $((256 * 1024 * 1024)) $KEY > /sys/fs/vdisk/session1/create_disk
cat /sys/fs/vdisk/session1/vdisk1/disk_id
cat /sys/fs/vdisk/session1/vdisk1/size
cat /sys/fs/vdisk/session1/vdisk1/disk_handle

dd if=/dev/urandom of=$WDIR/file bs=1M count=16
dd if=$WDIR/file of=/dev/vdisk1 bs=1M count=16
dd if=/dev/vdisk1 of=$WDIR/file2 bs=1M count=16

md5sum $WDIR/file $WDIR/file2

umount /mnt/vdisk1 || true
rm -rf /mnt/vdisk1
mkdir /mnt/vdisk1
mkfs.ext4 /dev/vdisk1
mount -t ext4 /dev/vdisk1 /mnt/vdisk1
