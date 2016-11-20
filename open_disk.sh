#!/bin/bash -xv
WDIR=temp

set -e

echo 1 > /sys/fs/vdisk/create_session
#echo 185.87.193.120 9111 > /sys/fs/vdisk/session1/connect
echo $1 9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q2w3e > /sys/fs/vdisk/session1/login

cat /sys/fs/vdisk/session1/session_id
KEY=`echo 1q2w3e | sha256sum | awk '{ print $1 }'`
echo $2 $KEY > /sys/fs/vdisk/session1/open_disk
cat /sys/fs/vdisk/session1/vdisk0/disk_id
cat /sys/fs/vdisk/session1/vdisk0/size
cat /sys/fs/vdisk/session1/vdisk0/disk_handle

umount /mnt/vdisk0 || true
rm -rf /mnt/vdisk0 || true
mkdir /mnt/vdisk0
mount -t ext4 /dev/vdisk0 /mnt/vdisk0
