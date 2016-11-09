#ifndef __VDISK_H__
#define __VDISK_H__

#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/zlib.h>

struct vdisk_kobject_holder {
	struct kobject kobj;
	struct completion completion;
};

static inline struct completion *vdisk_get_completion_from_kobject(
					struct kobject *kobj)
{
	return &container_of(kobj,
			     struct vdisk_kobject_holder, kobj)->completion;
}

struct vdisk {
	int number;
	struct request_queue *queue;
	struct gendisk *gdisk;
	struct list_head list;
	rwlock_t lock;
	wait_queue_head_t waitq;
	struct list_head req_list;
	struct vdisk_kobject_holder kobj_holder;
	u64 bps[2];
	u64 iops[2];
	u64 max_bps[2];
	u64 max_iops[2];
	u64 limit_bps[2];
	u64 limit_iops[2];
	u64 entropy[2];
	u64 size;
	bool releasing;
};

void vdisk_set_iops_limits(struct vdisk *disk, u64 *limit_iops, int len);

void vdisk_set_bps_limits(struct vdisk *disk, u64 *limit_bps, int len);

int vdisk_create(int number, u64 size);

int vdisk_delete(int number);

#endif
