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

#### Usage:
```sh

$ insmod vdisk.ko #load kernel module

$ echo mysession > /sys/fs/vdisk/create_session #create user session 

$ echo 52.8.178.233 9111 myaccount@gmail.com mypassword > /sys/fs/vdisk/mysession/connect

$ echo mydiskpassword | sha256sum | awk '{ print $1 }' #generate AES-256 key in hex form

$ echo mydisk mykey > /sys/fs/vdisk/mysession/open_disk #open disk existing 'mydisk' disk

$ echo mydisk 268435456 mykey > /sys/fs/vdisk/mysession/create_disk #or create new 'mydisk' disk, where 268435456 - size in bytes

$ cat /sys/fs/vdisk/mysession/mydisk/number #get device number

$ mkfs.ext4 /dev/vdisk{number}	#format disk as EXT4 file system

$ mkdir /mnt/mydisk && mount /dev/vdisk{number} /mnt/mydisk #mount disk file system

$ cd /mnt/mydisk && ... #work with disk data

$ umount /dev/vdisk{number} #unmount disk

$ echo mysession > /sys/fs/vdisk/delete_session #close disk and delete session

$ rmmod vdisk #unload kernel module

```
