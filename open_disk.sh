#!/bin/bash -xv
WDIR=temp

echo 1 > /sys/fs/vdisk/create_session
#echo 185.87.193.120:9111 > /sys/fs/vdisk/session1/connect
echo 127.0.0.1:9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q2w3e > /sys/fs/vdisk/session1/login

cat /sys/fs/vdisk/session1/session_id
KEY=`echo 1q2w3e | sha256sum | awk '{ print $1 }'`
echo 1 79 $KEY > /sys/fs/vdisk/session1/open_disk
cat /sys/fs/vdisk/session1/vdisk1/disk_id
cat /sys/fs/vdisk/session1/vdisk1/size
cat /sys/fs/vdisk/session1/vdisk1/disk_handle

umount /mnt/vdisk1
rm -rf /mnt/vdisk1
mkdir /mnt/vdisk1
mount -t ext4 /dev/vdisk1 /mnt/vdisk1
