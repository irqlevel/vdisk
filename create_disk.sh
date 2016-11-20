#!/bin/bash -xv
set -e

WDIR=temp

echo 1 > /sys/fs/vdisk/create_session
#echo 185.87.193.120 9111 > /sys/fs/vdisk/session1/connect
echo $1 9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q2w3e > /sys/fs/vdisk/session1/login

cat /sys/fs/vdisk/session1/session_id
KEY=`echo 1q2w3e | sha256sum | awk '{ print $1 }'`
echo $2 $((256 * 1024 * 1024)) $KEY > /sys/fs/vdisk/session1/create_disk
cat /sys/fs/vdisk/session1/vdisk0/disk_id
cat /sys/fs/vdisk/session1/vdisk0/size
cat /sys/fs/vdisk/session1/vdisk0/disk_handle

dd if=/dev/urandom of=$WDIR/file bs=1M count=16
dd if=$WDIR/file of=/dev/vdisk0 bs=1M count=16
dd if=/dev/vdisk0 of=$WDIR/file2 bs=1M count=16

md5sum $WDIR/file $WDIR/file2

umount /mnt/vdisk0 || true
rm -rf /mnt/vdisk0
mkdir /mnt/vdisk0
mkfs.ext4 /dev/vdisk0
mount -t ext4 /dev/vdisk0 /mnt/vdisk0
