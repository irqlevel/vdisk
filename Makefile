CURRDIR = $(shell pwd)
KERNEL_BUILD_PATH=/lib/modules/$(shell uname -r)/build

VDISK_MOD = vdisk-mod
VDISK_MOD_KO = $(VDISK_MOD).ko

vdisk-mod-y  += vdisk.o vdisk-sysfs.o vdisk-connection.o ksocket.o	\
		vdisk-trace.o vdisk-cache.o vdisk-malloc-checker.o

obj-m = $(VDISK_MOD).o

KBUILD_EXTRA_SYMBOLS = $(KERNEL_BUILD_PATH)/Module.symvers

ccflags-y := -I$(src) -g3	\
		-D __MALLOC_CHECKER__				\
		-D __MALLOC_CHECKER_STACK_TRACE__		\
		-D __MALLOC_CHECKER_FILL_CC__			\

all:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) modules
clean:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) clean
	rm -f *.o
	rm -rf temp/
