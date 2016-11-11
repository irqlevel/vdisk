#!/bin/bash -xv
WDIR=temp

echo 1 > /sys/fs/vdisk/session1/delete_disk
echo 1 > /sys/fs/vdisk/session1/logout
echo 1 > /sys/fs/vdisk/session1/disconnect
echo 1 > /sys/fs/vdisk/delete_session
