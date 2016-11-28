CURRDIR = $(shell pwd)
KERNEL_BUILD_PATH=/lib/modules/$(shell uname -r)/build

VDISK_MOD = vdisk
VDISK_MOD_KO = $(VDISK_MOD).ko

vdisk-y +=	vdisk-core.o vdisk-sysfs.o vdisk-connection.o ksocket.o	\
		vdisk-trace.o vdisk-cache.o vdisk-malloc-checker.o	\
		vdisk-helpers.o						\
		mbedtls-helpers.o					\
		mbedtls/aes.o mbedtls/rsa.o mbedtls/md.o mbedtls/sha1.o	\
		mbedtls/sha512.o mbedtls/sha256.o mbedtls/dhm.o	\
		mbedtls/ecp.o mbedtls/ecp_curves.o mbedtls/bignum.o	\
		mbedtls/md5.o mbedtls/pem.o mbedtls/des.o	\
		mbedtls/base64.o mbedtls/md_wrap.o mbedtls/ripemd160.o	\
		mbedtls/asn1parse.o mbedtls/asn1write.o mbedtls/oid.o	\
		mbedtls/ssl_cli.o mbedtls/ssl_tls.o mbedtls/x509.o	\
		mbedtls/cipher.o mbedtls/cipher_wrap.o mbedtls/gcm.o	\
		mbedtls/camellia.o mbedtls/blowfish.o mbedtls/arc4.o	\
		mbedtls/pk.o mbedtls/ecdh.o mbedtls/ccm.o		\
		mbedtls/ssl_ciphersuites.o mbedtls/x509_crt.o		\
		mbedtls/pk_wrap.o mbedtls/ecdsa.o mbedtls/hmac_drbg.o	\
		mbedtls/pkparse.o mbedtls/pkcs5.o mbedtls/pkcs12.o	\
		mbedtls/entropy.o mbedtls/ctr_drbg.o mbedtls/platform.o	\

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
