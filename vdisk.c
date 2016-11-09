/*
 * Copyright (C) 2016 Andrey Smetanin <irqlevel@gmail.com>
 *
 * This file is released under the GPL.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/mutex.h>
#include <linux/bitmap.h>
#include <net/sock.h>
#include <linux/un.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/kobject.h>
#include <linux/zlib.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/rwsem.h>

#include "vdisk.h"
#include "vdisk-sysfs.h"

#define CREATE_TRACE_POINTS
#include "vdisk-trace.h"

static inline void vdisk_trace_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	trace_printf(fmt, args);
	va_end(args);
}

static inline void vdisk_trace_error(int err, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	trace_error(err, fmt, args);
	va_end(args);
}

#define TRACE(fmt, ...)						\
do {								\
	vdisk_trace_printf("%s: " fmt,				\
				__func__, ##__VA_ARGS__);	\
} while (false)

#define TRACE_ERR(err, fmt, ...)			\
do {							\
	vdisk_trace_error(err, "%s: " fmt,		\
			      __func__, ##__VA_ARGS__);	\
} while (false)

#define VDISK_NUMBERS 256

struct vdisk_global {
	DECLARE_BITMAP(disk_numbers, VDISK_NUMBERS);
	struct list_head disk_list;
	struct rw_semaphore rw_sem;
};

static struct vdisk_global global_vdisk;

static struct vdisk_global *vdisk_get_global(void)
{
	return &global_vdisk;
}

void vdisk_set_iops_limits(struct vdisk *disk, u64 *limit_iops, int len)
{
	if (WARN_ON(len != 2))
		return;

	disk->limit_iops[0] = limit_iops[0];
	disk->limit_iops[1] = limit_iops[1];
}

void vdisk_set_bps_limits(struct vdisk *disk, u64 *limit_bps, int len)
{
	if (WARN_ON(len != 2))
		return;

	disk->limit_bps[0] = limit_bps[0];
	disk->limit_bps[1] = limit_bps[1];
}

static int vdisk_init_global(struct vdisk_global *glob)
{
	memset(glob, 0, sizeof(*glob));
	INIT_LIST_HEAD(&glob->disk_list);
	init_rwsem(&glob->rw_sem);
	return 0;
}

static void vdisk_release(struct vdisk *disk)
{
	struct vdisk_global *glob = vdisk_get_global();

	TRACE("disk 0x%p number %d releasing", disk, disk->number);

	vdisk_disk_sysfs_exit(disk);
	clear_bit(disk->number, glob->disk_numbers);
	kfree(disk);
}

static void vdisk_deinit_global(struct vdisk_global *glob)
{
	struct vdisk *curr, *tmp;

	down_write(&glob->rw_sem);
	list_for_each_entry_safe(curr, tmp, &glob->disk_list, list) {
		list_del_init(&curr->list);
		vdisk_release(curr);
	}
	up_write(&glob->rw_sem);
}

int vdisk_create(int number)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *disk;
	int r;

	if (number < 0 || number >= VDISK_NUMBERS)
		return -EINVAL;

	TRACE("creating disk %d", number);

	if (test_and_set_bit(number, glob->disk_numbers) != 0) {
		r = -EINVAL;
		goto fail;
	}

	disk = kzalloc(sizeof(*disk), GFP_KERNEL);
	if (!disk) {
		r = -ENOMEM;
		goto free_number;
	}

	disk->number = number;
	r = vdisk_disk_sysfs_init(disk);
	if (r)
		goto free_disk;

	down_write(&glob->rw_sem);
	TRACE("disk 0x%p number %d added", disk, disk->number);
	list_add_tail(&disk->list, &glob->disk_list);
	up_write(&glob->rw_sem);

	return 0;

free_disk:
	kfree(disk);
free_number:
	clear_bit(number, glob->disk_numbers);
fail:
	return r;
}

int vdisk_delete(int number)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *curr, *tmp;
	int r;

	TRACE("deleting disk %d", number);

	r = -ENOTTY;
	down_write(&glob->rw_sem);
	list_for_each_entry_safe(curr, tmp, &glob->disk_list, list) {
		if (curr->number == number) {
			list_del_init(&curr->list);
			vdisk_release(curr);
			r = 0;
			break;
		}
	}
	up_write(&glob->rw_sem);

	return r;
}

static int __init vdisk_init(void)
{
	struct vdisk_global *glob = vdisk_get_global();
	int r;

	r = vdisk_init_global(glob);
	if (r) {
		pr_err("vdisk: cant init global, r %d", r);
		return r;
	}

	r = vdisk_sysfs_init();
	if (r) {
		pr_err("vdisk: cant create root kobject, r %d", r);
		goto deinit_global;
	}

	pr_info("vdisk: inited, vdisk_init=0x%p global=0x%p", vdisk_init, glob);
	return 0;

deinit_global:
	vdisk_deinit_global(glob);
	return r;
}

static void __exit vdisk_exit(void)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *curr, *tmp;

	down_write(&glob->rw_sem);
	list_for_each_entry_safe(curr, tmp, &glob->disk_list, list) {
		list_del_init(&curr->list);
		vdisk_release(curr);
	}
	up_write(&glob->rw_sem);

	vdisk_sysfs_exit();
	vdisk_deinit_global(glob);

	pr_info("vdisk: exited");
}

module_init(vdisk_init)
module_exit(vdisk_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("Virtual disk");
MODULE_LICENSE("GPL");
