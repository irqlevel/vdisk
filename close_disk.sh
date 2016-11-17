#!/bin/bash -xv
WDIR=temp

umount /dev/vdisk1
cat /sys/fs/vdisk/session1/vdisk1/disk_id
echo 1 > /sys/fs/vdisk/session1/close_disk
echo 1 > /sys/fs/vdisk/delete_session
