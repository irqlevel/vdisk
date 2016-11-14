#ifndef __VDISK_MALLOC_CHECKER_H__
#define __VDISK_MALLOC_CHECKER_H__

#include <linux/slab.h>

int malloc_checker_init(void);
void malloc_checker_deinit(void);

void *malloc_checker_kmalloc(size_t size, gfp_t flags);
void malloc_checker_kfree(void *ptr);

#endif
