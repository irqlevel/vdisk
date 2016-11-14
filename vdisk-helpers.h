#ifndef __VDISK_HELPERS_H__
#define __VDISK_HELPERS_H__

#include <linux/version.h>

static inline unsigned long hash_pointer(void *ptr)
{
	unsigned long val = (unsigned long)ptr;
	unsigned long hash, i, c;

	hash = 5381;
	val = val >> 3;
	for (i = 0; i < sizeof(val); i++) {
		c = (unsigned char)val & 0xFF;
		hash = ((hash << 5) + hash) + c;
		val = val >> 8;
	}

	return hash;
}

static inline const char *truncate_file_name(const char *file_name)
{
	char *base;

	base = strrchr(file_name, '/');
	if (base)
		return ++base;
	else
		return file_name;
}

#define PRINTK(fmt, ...)    \
	pr_info("vdisk: " fmt, ##__VA_ARGS__)

#endif
