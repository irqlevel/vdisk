#!/bin/bash -xv
WDIR=temp

umount /dev/vdisk1
echo 1 > /sys/fs/vdisk/session1/delete_disk
echo 1 > /sys/fs/vdisk/delete_session
