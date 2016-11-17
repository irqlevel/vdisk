#ifndef __VDISK_HELPERS_H__
#define __VDISK_HELPERS_H__

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>

unsigned long vdisk_hash_pointer(void *ptr);

const char *vdisk_truncate_file_name(const char *file_name);

#define PRINTK(fmt, ...)    \
	pr_info("vdisk: " fmt, ##__VA_ARGS__)

int vdisk_hex_to_byte(unsigned char c);

int vdisk_hex_to_bytes(char *hex, int hex_len, unsigned char *dst,
		       int dst_len);

#endif
