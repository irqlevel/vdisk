CURRDIR = $(shell pwd)
KERNEL_BUILD_PATH=/lib/modules/$(shell uname -r)/build

VDISK_MOD = vdisk-mod
VDISK_MOD_KO = $(VDISK_MOD).ko

vdisk-mod-y  += vdisk.o vdisk-sysfs.o vdisk-connection.o ksocket.o
obj-m = $(VDISK_MOD).o

KBUILD_EXTRA_SYMBOLS = $(KERNEL_BUILD_PATH)/Module.symvers

ccflags-y := -I$(src) -g3

all:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) modules
clean:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) clean
	rm -f *.o
	rm -rf temp/
