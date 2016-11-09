#ifndef __VDISK_SYSFS_H__
#define __VDISK_SYSFS_H__

#include <linux/sysfs.h>
#include "vdisk.h"

int vdisk_disk_sysfs_init(struct vdisk *vdisk);

void vdisk_disk_sysfs_exit(struct vdisk *vdisk);

int vdisk_sysfs_init(void);
void vdisk_sysfs_exit(void);

#endif
