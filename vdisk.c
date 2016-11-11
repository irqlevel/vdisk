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
#include <linux/kthread.h>

#include "vdisk.h"
#include "vdisk-sysfs.h"
#include "vdisk-connection.h"


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

static struct vdisk_global global_context;

static struct vdisk_global *vdisk_get_global(void)
{
	return &global_context;
}

void vdisk_disk_set_iops_limits(struct vdisk *disk, u64 *limit_iops, int len)
{
	if (WARN_ON(len != 2))
		return;

	disk->limit_iops[0] = limit_iops[0];
	disk->limit_iops[1] = limit_iops[1];
}

void vdisk_disk_set_bps_limits(struct vdisk *disk, u64 *limit_bps, int len)
{
	if (WARN_ON(len != 2))
		return;

	disk->limit_bps[0] = limit_bps[0];
	disk->limit_bps[1] = limit_bps[1];
}

int vdisk_session_connect(struct vdisk_session *session, u32 ip, u16 port)
{
	int r;

	TRACE("session 0x%p connecting ip 0x%x port %u", session, ip, port);

	r = vdisk_con_connect(&session->con, ip, port);

	TRACE("session 0x%p connect ip 0x%x port %u, r %d",
	      session, ip, port, r);

	return r;
}

int vdisk_session_disconnect(struct vdisk_session *session)
{
	int r;

	TRACE("session 0x%p disconnecting", session);

	r = vdisk_con_close(&session->con);

	TRACE("session 0x%p disconnect r %d", session, r);

	return r;
}

static int vdisk_init_global(struct vdisk_global *glob)
{
	int r;
	int major;

	memset(glob, 0, sizeof(*glob));
	INIT_LIST_HEAD(&glob->session_list);
	init_rwsem(&glob->rw_sem);

	r = register_blkdev(0, VDISK_BLOCK_DEV_NAME);
	if (r < 0)
		return r;

	major = r;

	r = vdisk_sysfs_init(&glob->kobj_holder, fs_kobj, &vdisk_global_ktype,
			"%s", "vdisk");
	if (r)
		goto free_blk;

	glob->major = major;
	pr_info("vdisk: major %d", glob->major);
	return 0;

free_blk:
	unregister_blkdev(major, VDISK_BLOCK_DEV_NAME);
	return r;
}

static void vdisk_release(struct vdisk *disk)
{
	struct vdisk_global *glob = vdisk_get_global();

	TRACE("disk 0x%p number %d releasing", disk, disk->number);

	del_gendisk(disk->gdisk);
	blk_cleanup_queue(disk->queue);

	TRACE("disk 0x%p stopping thread", disk);

	kthread_stop(disk->thread);
	put_task_struct(disk->thread);

	TRACE("disk 0x%p thread stopped", disk);

	put_disk(disk->gdisk);

	vdisk_sysfs_deinit(&disk->kobj_holder);

	clear_bit(disk->number, glob->disk_numbers);
	kfree(disk);

	TRACE("disk 0x%p released", disk);
}

static void vdisk_session_release(struct vdisk_session *session)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *curr, *tmp;

	TRACE("session 0x%p number %d releasing", session, session->number);

	vdisk_con_deinit(&session->con);

	down_write(&session->rw_sem);
	list_for_each_entry_safe(curr, tmp, &session->disk_list, list) {
		list_del_init(&curr->list);
		vdisk_release(curr);
	}
	up_write(&session->rw_sem);

	vdisk_sysfs_deinit(&session->kobj_holder);

	clear_bit(session->number, glob->session_numbers);

	kfree(session);

	TRACE("sesson 0x%p released", session);
}

static void vdisk_deinit_global(struct vdisk_global *glob)
{
	struct vdisk_session *curr, *tmp;

	down_write(&glob->rw_sem);
	list_for_each_entry_safe(curr, tmp, &glob->session_list, list) {
		list_del_init(&curr->list);
		vdisk_session_release(curr);
	}
	up_write(&glob->rw_sem);

	vdisk_sysfs_deinit(&glob->kobj_holder);

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

static int vdisk_thread_routine(void *data)
{
	struct vdisk *disk = data;
	struct vdisk_bio *vbio, *tmp;
	struct list_head req_list;
	struct bio *bio;
	unsigned long irq_flags;

	TRACE("disk 0x%p thread starting", disk);

	for (;;) {
		wait_event_interruptible(disk->waitq,
			(kthread_should_stop() ||
			 !list_empty(&disk->req_list)));
		if (kthread_should_stop()) {
			TRACE("disk 0x%p thread should stop", disk);
			break;
		}

		write_lock_irqsave(&disk->lock, irq_flags);
		vbio = list_first_entry_or_null(&disk->req_list,
						struct vdisk_bio, list);
		if (vbio)
			list_del_init(&vbio->list);
		write_unlock_irqrestore(&disk->lock, irq_flags);
		if (!vbio)
			continue;

		bio = vbio->bio;
		TRACE("disk 0x%p cancel bio 0x%p rw 0x%x sector %lu size %u",
			disk, bio, bio->bi_rw, bio->bi_iter.bi_sector,
			bio->bi_iter.bi_size);
		bio_io_error(bio);
		bio_put(bio);
		kfree(vbio);
	}

	TRACE("disk 0x%p thread stopping", disk);

	/* cancel all requests */
	INIT_LIST_HEAD(&req_list);
	write_lock_irqsave(&disk->lock, irq_flags);
	list_splice_init(&disk->req_list, &req_list);
	write_unlock_irqrestore(&disk->lock, irq_flags);

	list_for_each_entry_safe(vbio, tmp, &req_list, list) {
		list_del_init(&vbio->list);
		bio = vbio->bio;
		TRACE("disk 0x%p cancel bio 0x%p rw 0x%x sector %lu size %u",
			disk, bio, bio->bi_rw, bio->bi_iter.bi_sector,
			bio->bi_iter.bi_size);
		bio_io_error(bio);
		bio_put(bio);
		kfree(vbio);
	}

	TRACE("disk 0x%p thread stopped", disk);
	return 0;
}

static blk_qc_t vdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct vdisk *disk = bdev->bd_disk->private_data;
	struct vdisk_bio *vbio;
	sector_t sector;
	unsigned long irq_flags;

	sector = bio->bi_iter.bi_sector;
	TRACE("disk 0x%p bio 0x%p rw 0x%x sector %lu size %u",
	      disk, bio, bio->bi_rw, sector, bio->bi_iter.bi_size);

	if (bio_end_sector(bio) > get_capacity(bdev->bd_disk))
		goto io_error;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		if (sector & ((PAGE_SIZE >> SECTOR_SHIFT) - 1) ||
		    bio->bi_iter.bi_size & ~PAGE_MASK)
			goto io_error;
	}

	vbio = kmalloc(sizeof(*vbio), GFP_NOIO);
	if (!vbio)
		goto io_error;
	bio_get(bio);
	vbio->bio = bio;

	write_lock_irqsave(&disk->lock, irq_flags);
	list_add_tail(&vbio->list, &disk->req_list);
	write_unlock_irqrestore(&disk->lock, irq_flags);

	wake_up_interruptible(&disk->waitq);
	return BLK_QC_T_NONE;

io_error:
	TRACE("disk 0x%p cancel bio 0x%p rw 0x%x sector %lu size %u",
	      disk, bio, bio->bi_rw, sector, bio->bi_iter.bi_size);

	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int vdisk_session_start_disk(struct vdisk_session *session,
				    int number, u64 size, u64 disk_id)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *disk;
	struct gendisk *gdisk;
	struct task_struct *thread;
	int r;

	if (number < 0 || number >= VDISK_DISK_NUMBER_MAX)
		return -EINVAL;
	if (size & 511 || size & 4095)
		return -EINVAL;

	TRACE("creating disk %d", number);

	if (test_and_set_bit(number, glob->disk_numbers) != 0)
		return -EINVAL;

	disk = kzalloc(sizeof(*disk), GFP_KERNEL);
	if (!disk) {
		r = -ENOMEM;
		goto free_number;
	}
	disk->session = session;
	disk->number = number;
	disk->size = size;
	disk->disk_id = disk_id;
	init_waitqueue_head(&disk->waitq);
	rwlock_init(&disk->lock);
	INIT_LIST_HEAD(&disk->req_list);

	thread = kthread_create(vdisk_thread_routine, disk,
				"vdisk%d-thread", disk->number);
	if (IS_ERR(thread)) {
		r = PTR_ERR(thread);
		goto free_disk;
	}

	get_task_struct(thread);
	disk->thread = thread;
	wake_up_process(disk->thread);

	disk->queue = blk_alloc_queue(GFP_KERNEL);
	if (!disk->queue) {
		r = -ENOMEM;
		goto free_thread;
	}

	blk_queue_make_request(disk->queue, vdisk_make_request);
	blk_queue_max_hw_sectors(disk->queue, 1024);
	blk_queue_bounce_limit(disk->queue, BLK_BOUNCE_ANY);

	disk->queue->limits.discard_granularity = PAGE_SIZE;
	disk->queue->limits.max_discard_sectors = UINT_MAX;
	disk->queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, disk->queue);

	gdisk = alloc_disk(1);
	if (!gdisk) {
		r = -ENOMEM;
		goto free_queue;
	}

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

	r = vdisk_sysfs_init(&disk->kobj_holder, &session->kobj_holder.kobj,
			&vdisk_disk_ktype, "vdisk%d", disk->number);
	if (r)
		goto free_gdisk;

	down_write(&session->rw_sem);
	TRACE("session 0x%p disk 0x%p gdisk 0x%p number %d added",
	      session, disk, gdisk, disk->number);
	list_add_tail(&disk->list, &session->disk_list);
	up_write(&session->rw_sem);

	add_disk(gdisk);

	return 0;

free_gdisk:
	put_disk(gdisk);
free_queue:
	blk_cleanup_queue(disk->queue);
free_thread:
	kthread_stop(disk->thread);
	put_task_struct(disk->thread);
free_disk:
	kfree(disk);
free_number:
	clear_bit(number, glob->disk_numbers);
	return r;
}

int vdisk_session_create_disk(struct vdisk_session *session,
			      int number, u64 size)
{
	u64 disk_id;
	int r;

	r = vdisk_con_disk_create(&session->con, size, &disk_id);
	if (r)
		return r;

	TRACE("disk disk_id %llu size %llu created", disk_id, size);
	r = vdisk_session_start_disk(session, number, size, disk_id);
	if (r)
		goto delete_disk;

	return 0;

delete_disk:
	vdisk_con_disk_delete(&session->con, disk_id);
	return r;
}

int vdisk_session_delete_disk(struct vdisk_session *session, int number)
{
	struct vdisk *curr, *tmp;
	u64 disk_id;
	int r;

	TRACE("deleting disk %d", number);

	r = -ENOTTY;
	down_write(&session->rw_sem);
	list_for_each_entry_safe(curr, tmp, &session->disk_list, list) {
		if (curr->number == number) {
			list_del_init(&curr->list);
			disk_id = curr->disk_id;
			vdisk_release(curr);
			r = vdisk_con_disk_delete(&session->con, disk_id);
			break;
		}
	}
	up_write(&session->rw_sem);

	return r;
}

int vdisk_session_open_disk(struct vdisk_session *session, int number,
			    u64 disk_id)
{
	return -EINVAL;
}

int vdisk_session_close_disk(struct vdisk_session *session, int number)
{
	return -EINVAL;
}

int vdisk_session_login(struct vdisk_session *session,
			char *user_name, char *password)
{
	int r;

	r = vdisk_con_login(&session->con, user_name, password);
	TRACE("session 0x%p login session_id %s r %d ",
	      session, session->con.session_id, r);

	return r;
}

int vdisk_session_logout(struct vdisk_session *session)
{
	int r;

	r = vdisk_con_logout(&session->con);
	TRACE("session 0x%p logout r %d", session, r);
	return r;
}

int vdisk_global_create_session(struct vdisk_global *glob, int number)
{
	struct vdisk_session *session;
	int r;

	if (WARN_ON(glob != vdisk_get_global()))
		return -EINVAL;
	if (number < 0 || number >= VDISK_SESSION_NUMBER_MAX)
		return -EINVAL;

	TRACE("creating session %d", number);

	if (test_and_set_bit(number, glob->session_numbers) != 0)
		return -EINVAL;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session) {
		r = -ENOMEM;
		goto free_number;
	}
	init_rwsem(&session->rw_sem);
	INIT_LIST_HEAD(&session->disk_list);
	session->number = number;

	r = vdisk_con_init(&session->con);
	if (r)
		goto free_session;

	r = vdisk_sysfs_init(&session->kobj_holder, &glob->kobj_holder.kobj,
		&vdisk_session_ktype, "session%d", session->number);
	if (r)
		goto free_con;

	down_write(&glob->rw_sem);
	TRACE("session 0x%p number %d added", session, session->number);
	list_add_tail(&session->list, &glob->session_list);
	up_write(&glob->rw_sem);

	return 0;

free_con:
	vdisk_con_deinit(&session->con);
free_session:
	kfree(session);
free_number:
	clear_bit(number, glob->session_numbers);
	return r;
}

int vdisk_global_delete_session(struct vdisk_global *glob, int number)
{
	struct vdisk_session *curr, *tmp;
	int r;

	if (WARN_ON(glob != vdisk_get_global()))
		return -EINVAL;

	TRACE("deleting session %d", number);

	r = -ENOTTY;
	down_write(&glob->rw_sem);
	list_for_each_entry_safe(curr, tmp, &glob->session_list, list) {
		if (curr->number == number) {
			list_del_init(&curr->list);
			vdisk_session_release(curr);
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

	pr_info("vdisk: inited, vdisk_init=0x%p global=0x%p", vdisk_init, glob);
	return 0;
}

static void __exit vdisk_exit(void)
{
	struct vdisk_global *glob = vdisk_get_global();

	vdisk_deinit_global(glob);

	pr_info("vdisk: exited");
}

module_init(vdisk_init)
module_exit(vdisk_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("Virtual disk");
MODULE_LICENSE("GPL");
