#!/bin/bash -xv
WDIR=temp

echo 1 > /sys/fs/vdisk/create_session
echo 127.0.0.1:9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q > /sys/fs/vdisk/session1/login
cat /sys/fs/vdisk/session1/session_id
echo 1 $((256 * 1024 * 1024)) > /sys/fs/vdisk/session1/create_disk
cat /sys/fs/vdisk/session1/vdisk1/disk_id
cat /sys/fs/vdisk/session1/vdisk1/size
cat /sys/fs/vdisk/session1/vdisk1/disk_handle
mkfs.ext4 /dev/vdisk1
rm -rf /mnt/vdisk1
mkdir /mnt/vdisk1
mount -t ext4 /dev/vdisk1 /mnt/vdisk1
