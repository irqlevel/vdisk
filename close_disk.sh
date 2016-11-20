#!/bin/bash -xv
WDIR=temp

set -e
umount /dev/vdisk0 || true
cat /sys/fs/vdisk/session1/vdisk0/disk_id
echo $1 > /sys/fs/vdisk/session1/close_disk
