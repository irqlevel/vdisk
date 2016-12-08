### Vdisk - secure network block device

#### Features:
1. Client side encryption
2. TLS

#### Build:
```sh
$ git clone https://github.com/irqlevel/vdisk.git
$ cd vdisk
$ make
```

#### Server:
https://vdiskhub.com/ - web console

store.vdiskhub.com:9111 (52.52.175.249:9111) - storage server

#### Usage:
```sh

#enable DNS lookup in kernel
$ apt-get install keyutils

#load kernel module
$ insmod vdisk.ko

#create user session
$ echo mysession > /sys/fs/vdisk/create_session

#connect to server store.vdiskhub.com:9111 or 52.8.178.233:9111
$ echo store.vdiskhub.com 9111 myaccount@mymail.com mypassword > /sys/fs/vdisk/mysession/connect

#generate AES-256 key in hex form
$ echo mydiskpassword | sha256sum | awk '{ print $1 }'

#open existing 'mydisk' disk
$ echo mydisk mykey > /sys/fs/vdisk/mysession/open_disk

#or create new 'mydisk' with size 256MB
$ echo mydisk 256 mykey > /sys/fs/vdisk/mysession/create_disk

#get block device number
$ cat /sys/fs/vdisk/mysession/mydisk/number

#format disk as EXT4 file system
$ mkfs.ext4 /dev/vdisk{number}

#mount disk
$ mkdir /mnt/mydisk && mount /dev/vdisk{number} /mnt/mydisk

#work with data
$ cd /mnt/mydisk && ...

#unmount disk
$ umount /dev/vdisk{number} #unmount disk

#close disk and delete session
$ echo mysession > /sys/fs/vdisk/delete_session

#unload kernel module
$ rmmod vdisk

```
