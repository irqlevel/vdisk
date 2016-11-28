#!/bin/bash -xv
WDIR=temp
set -e
echo $1 > /sys/fs/vdisk/delete_session
