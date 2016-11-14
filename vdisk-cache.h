#ifndef __VDISK_CACHE_H__
#define __VDISK_CACHE_H__

#include "vdisk.h"

int vdisk_cache_init(struct vdisk *disk);

void vdisk_cache_deinit(struct vdisk *disk);

int vdisk_cache_discard(struct vdisk *disk, sector_t sector, u32 len);

int vdisk_cache_copy_from(struct vdisk *disk, void *buf, u64 off,
			  u32 len, unsigned long rw);

int vdisk_cache_copy_to(struct vdisk *disk, void *buf, u64 off,
			u32 len, unsigned long rw);

void vdisk_cache_set_limit(struct vdisk *disk, u64 limit);

#endif
