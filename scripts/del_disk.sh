#!/bin/bash -xv
WDIR=temp

SESSION=$1
DISK=$2

DISK_NUM=`cat /sys/fs/vdisk/$SESSION/$DISK/number`
umount /dev/vdisk$DISK_NUM
echo $DISK > /sys/fs/vdisk/$SESSION/delete_disk
