#ifndef __VDISK_SYSFS_H__
#define __VDISK_SYSFS_H__

#include <linux/sysfs.h>
#include <linux/kobject.h>
#include "vdisk.h"

extern struct kobj_type vdisk_disk_ktype;
extern struct kobj_type vdisk_session_ktype;
extern struct kobj_type vdisk_global_ktype;

int vdisk_sysfs_init(struct vdisk_kobject_holder *holder, struct kobject *root,
		     struct kobj_type *ktype, const char *fmt, ...);

void vdisk_sysfs_deinit(struct vdisk_kobject_holder *holder);

#endif
