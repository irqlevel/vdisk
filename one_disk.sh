#!/bin/bash -xv
WDIR=temp

echo 1 > /sys/fs/vdisk/create_session
echo 127.0.0.1:9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q > /sys/fs/vdisk/session1/login
cat /sys/fs/vdisk/session1/session_id
echo 1 268435456 > /sys/fs/vdisk/session1/create_disk
cat /sys/fs/vdisk/session1/vdisk1/disk_id
cat /sys/fs/vdisk/session1/vdisk1/size
cat /sys/fs/vdisk/session1/vdisk1/disk_handle
