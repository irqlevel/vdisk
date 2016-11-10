#!/bin/bash -xv
WDIR=temp

echo 1 > /sys/fs/vdisk/create_session
echo 127.0.0.1:9111 > /sys/fs/vdisk/session1/connect
echo a@b.com 1q > /sys/fs/vdisk/session1/login
echo 1 > /sys/fs/vdisk/session1/logout
echo 1 > /sys/fs/vdisk/session1/disconnect
echo 1 > /sys/fs/vdisk/delete_session 
