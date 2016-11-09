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
#include <linux/cdrom.h>

#include "vdisk.h"
#include "vdisk-sysfs.h"

#define CREATE_TRACE_POINTS
#include "vdisk-trace.h"

#define VDISK_BLOCK_DEV_NAME "vdisk"

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
	int major;
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
	int r;

	memset(glob, 0, sizeof(*glob));
	INIT_LIST_HEAD(&glob->disk_list);
	init_rwsem(&glob->rw_sem);

	r = register_blkdev(0, VDISK_BLOCK_DEV_NAME);
	if (r < 0)
		return r;

	glob->major = r;
	pr_info("vdisk: major %d", glob->major);
	return 0;
}

static void vdisk_release(struct vdisk *disk)
{
	struct vdisk_global *glob = vdisk_get_global();

	TRACE("disk 0x%p number %d releasing", disk, disk->number);

	vdisk_disk_sysfs_exit(disk);

	del_gendisk(disk->gdisk);
	blk_cleanup_queue(disk->queue);
	put_disk(disk->gdisk);

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

	unregister_blkdev(glob->major, VDISK_BLOCK_DEV_NAME);
}

static int vdisk_ioctl(struct block_device *bdev, fmode_t mode,
		       unsigned int cmd, unsigned long arg)
{
	int r;
	struct vdisk *disk = bdev->bd_disk->private_data;

	TRACE("disk 0x%p cmd 0x%lx arg 0x%lx", disk, cmd, arg);

	r = -EINVAL;
	switch (cmd) {
	case BLKFLSBUF:
		r = 0;
		break;
	case CDROM_GET_CAPABILITY:
		r = -ENOIOCTLCMD;
		break;
	default:
		break;
	}

	TRACE("disk 0x%p cmd 0x%lx arg 0x%lx r %d", disk, cmd, arg, r);

	return r;
}

static const struct block_device_operations vdisk_fops = {
	.owner = THIS_MODULE,
	.ioctl = vdisk_ioctl,
};

static blk_qc_t vdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct vdisk *disk = bdev->bd_disk->private_data;
	sector_t sector;

	sector = bio->bi_iter.bi_sector;
	TRACE("disk 0x%p bdev 0x%p bio 0x%p rw 0x%x sector %lu size %u",
	      disk, bdev, bio, bio->bi_rw, sector, bio->bi_iter.bi_size);

	if (bio_end_sector(bio) > get_capacity(bdev->bd_disk))
		goto io_error;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		if (sector & ((PAGE_SIZE >> SECTOR_SHIFT) - 1) ||
		    bio->bi_iter.bi_size & ~PAGE_MASK)
			goto io_error;
	}

io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

int vdisk_create(int number, u64 size)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *disk;
	struct gendisk *gdisk;
	int r;

	if (number < 0 || number >= VDISK_NUMBERS)
		return -EINVAL;
	if (size & 511 || size & 4095)
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
	disk->size = size;
	init_waitqueue_head(&disk->waitq);
	rwlock_init(&disk->lock);
	INIT_LIST_HEAD(&disk->req_list);
	disk->queue = blk_alloc_queue(GFP_KERNEL);
	if (!disk->queue)
		goto free_disk;


	blk_queue_make_request(disk->queue, vdisk_make_request);
	blk_queue_max_hw_sectors(disk->queue, 1024);
	blk_queue_bounce_limit(disk->queue, BLK_BOUNCE_ANY);

	disk->queue->limits.discard_granularity = PAGE_SIZE;
	disk->queue->limits.max_discard_sectors = UINT_MAX;
	disk->queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, disk->queue);

	gdisk = alloc_disk(1);
	if (!gdisk)
		goto free_queue;

	gdisk->major = glob->major;
	gdisk->first_minor = disk->number;
	gdisk->fops = &vdisk_fops;
	gdisk->private_data = disk;
	gdisk->queue = disk->queue;
	gdisk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(gdisk->disk_name, sizeof(gdisk->disk_name),
		 VDISK_BLOCK_DEV_NAME"%d", disk->number);
	set_capacity(gdisk, size / 512);
	disk->gdisk = gdisk;

	r = vdisk_disk_sysfs_init(disk);
	if (r)
		goto free_gdisk;

	down_write(&glob->rw_sem);
	TRACE("disk 0x%p gdisk 0x%p number %d added",
	      disk, gdisk, disk->number);
	list_add_tail(&disk->list, &glob->disk_list);
	up_write(&glob->rw_sem);

	add_disk(gdisk);

	return 0;

free_gdisk:
	put_disk(gdisk);
free_queue:
	blk_cleanup_queue(disk->queue);
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
