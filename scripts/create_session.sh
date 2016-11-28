#!/bin/bash -xv
set -e

WDIR=temp
SERVER=$1
SESSION=$2

echo $SESSION > /sys/fs/vdisk/create_session
echo $SERVER 9111 a@b.com 1q2w3e > /sys/fs/vdisk/$SESSION/connect
