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
#include "vdisk-trace-helpers.h"
#include "vdisk-cache.h"
#include "vdisk-malloc-checker.h"
#include "vdisk-helpers.h"
#include "mbedtls-helpers.h"

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

int vdisk_session_connect(struct vdisk_session *session, char *host, u16 port)
{
	int r;

	TRACE("session 0x%p connecting host %s port %u", session, host, port);

	r = vdisk_con_connect(&session->con, host, port);

	TRACE("session 0x%p connect host %s port %u, r %d",
	      session, host, port, r);

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
	PRINTK("major %d", glob->major);
	return 0;

free_blk:
	unregister_blkdev(major, VDISK_BLOCK_DEV_NAME);
	return r;
}

static void vdisk_queue_deinit(struct vdisk *disk, int index)
{
	struct vdisk_queue *queue = &disk->queue[index];

	vdisk_con_close(&queue->con);
	vdisk_con_deinit(&queue->con);
	kthread_stop(queue->thread);
	put_task_struct(queue->thread);
	WARN_ON(!list_empty(&queue->req_list));
}

static int vdisk_release(struct vdisk *disk)
{
	struct vdisk_global *glob = vdisk_get_global();
	int r, i;

	TRACE("disk 0x%p number %d releasing", disk, disk->number);

	del_gendisk(disk->gdisk);

	hrtimer_cancel(&disk->renew_timer);
	destroy_workqueue(disk->wq);

	for (i = 0; i < ARRAY_SIZE(disk->queue); i++)
		vdisk_queue_deinit(disk, i);

	vdisk_cache_deinit(disk);

	r = vdisk_con_close_disk(&disk->session->con, disk->disk_id,
				 disk->disk_handle);

	TRACE("disk 0x%p close disk r %d", disk, r);

	blk_cleanup_queue(disk->req_queue);

	put_disk(disk->gdisk);

	vdisk_sysfs_deinit(&disk->kobj_holder);

	clear_bit(disk->number, glob->disk_numbers);
	vdisk_kfree(disk);

	TRACE("disk 0x%p released", disk);
	return r;
}

static void vdisk_session_release(struct vdisk_session *session)
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *curr, *tmp;

	TRACE("session 0x%p number %d releasing", session, session->number);

	down_write(&session->rw_sem);
	list_for_each_entry_safe(curr, tmp, &session->disk_list, list) {
		list_del_init(&curr->list);
		vdisk_release(curr);
	}
	up_write(&session->rw_sem);

	vdisk_con_close(&session->con);
	vdisk_con_deinit(&session->con);

	vdisk_sysfs_deinit(&session->kobj_holder);

	clear_bit(session->number, glob->session_numbers);

	vdisk_kfree(session);

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

static int vdisk_do_bvec(struct vdisk_queue *queue, struct page *page,
			 u32 len, u32 offset, unsigned long rw, sector_t sector)
{
	void *addr;
	u64 off;
	int r;

	off = sector << SECTOR_SHIFT;
	addr = kmap(page);
	if (!(rw & REQ_WRITE))
		r = vdisk_cache_copy_from(queue, (unsigned char *)addr + offset,
					  off, len, rw);
	else
		r = vdisk_cache_copy_to(queue, (unsigned char *)addr + offset,
					off, len, rw);
	kunmap(page);
	return 0;
}

static void vdisk_process_bio(struct vdisk_queue *queue, struct bio *bio)
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	sector_t sector;
	u32 len, size;
	int r;

	TRACE("disk 0x%p q %d process bio 0x%p rw 0x%x sector %lu size %u",
	      queue->disk, queue->index, bio, bio->bi_rw,
	      bio->bi_iter.bi_sector, bio->bi_iter.bi_size);

	sector = bio->bi_iter.bi_sector;
	size = bio->bi_iter.bi_size;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		r = vdisk_cache_discard(queue, sector, size);
		if (r)
			goto io_error;

		goto complete;
	}

	bio_for_each_segment(bvec, bio, iter) {
		len = bvec.bv_len;
		r = vdisk_do_bvec(queue, bvec.bv_page, len,
				  bvec.bv_offset, bio->bi_rw, sector);
		if (r)
			goto io_error;
		sector += len >> SECTOR_SHIFT;
	}

complete:
	bio_endio(bio);
	return;

io_error:
	bio_io_error(bio);
}

static int vdisk_thread_routine(void *data)
{
	struct vdisk_queue *queue = data;
	struct vdisk_bio *vbio, *tmp;
	struct list_head req_list;
	struct bio *bio;
	unsigned long irq_flags;

	TRACE("disk 0x%p q %d thread starting", queue->disk, queue->index);

	for (;;) {
		wait_event_interruptible(queue->waitq,
			(kthread_should_stop() ||
			 !list_empty(&queue->req_list)));
		if (kthread_should_stop()) {
			TRACE("disk 0x%p q %d thread should stop",
			      queue->disk, queue->index);
			break;
		}

		write_lock_irqsave(&queue->lock, irq_flags);
		vbio = list_first_entry_or_null(&queue->req_list,
						struct vdisk_bio, list);
		if (vbio)
			list_del_init(&vbio->list);
		write_unlock_irqrestore(&queue->lock, irq_flags);
		if (!vbio)
			continue;

		bio = vbio->bio;
		vdisk_process_bio(queue, bio);
		bio_put(bio);
		vdisk_kfree(vbio);
	}

	TRACE("disk 0x%p q %d thread stopping", queue->disk, queue->index);

	/* cancel all requests */
	INIT_LIST_HEAD(&req_list);
	write_lock_irqsave(&queue->lock, irq_flags);
	list_splice_init(&queue->req_list, &req_list);
	write_unlock_irqrestore(&queue->lock, irq_flags);

	list_for_each_entry_safe(vbio, tmp, &req_list, list) {
		list_del_init(&vbio->list);
		bio = vbio->bio;
		TRACE("disk 0x%p q %d cancel bio 0x%p rw 0x%x sec %lu size %u",
			queue->disk, queue->index, bio, bio->bi_rw,
			bio->bi_iter.bi_sector, bio->bi_iter.bi_size);
		bio_io_error(bio);
		bio_put(bio);
		vdisk_kfree(vbio);
	}

	TRACE("disk 0x%p q %d thread stopped", queue->disk, queue->index);
	return 0;
}

static blk_qc_t vdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct vdisk *disk = bdev->bd_disk->private_data;
	struct vdisk_bio *vbio;
	struct vdisk_queue *queue;
	sector_t sector;
	unsigned long irq_flags;
	int cpu;

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

	vbio = vdisk_kmalloc(sizeof(*vbio), GFP_NOIO);
	if (!vbio)
		goto io_error;
	bio_get(bio);
	vbio->bio = bio;

	cpu = get_cpu();
	queue = &disk->queue[cpu % ARRAY_SIZE(disk->queue)];
	put_cpu();

	write_lock_irqsave(&queue->lock, irq_flags);
	list_add_tail(&vbio->list, &queue->req_list);
	write_unlock_irqrestore(&queue->lock, irq_flags);

	wake_up_interruptible(&queue->waitq);
	return BLK_QC_T_NONE;

io_error:
	TRACE("disk 0x%p cancel bio 0x%p rw 0x%x sector %lu size %u",
	      disk, bio, bio->bi_rw, sector, bio->bi_iter.bi_size);

	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int vdisk_queue_init(struct vdisk *disk, int index)
{
	struct vdisk_queue *queue;
	struct task_struct *thread;
	int r;

	if (WARN_ON(index >= ARRAY_SIZE(disk->queue)))
		return -EINVAL;

	queue = &disk->queue[index];
	queue->index = index;
	queue->disk = disk;
	INIT_LIST_HEAD(&queue->req_list);
	init_waitqueue_head(&queue->waitq);
	rwlock_init(&queue->lock);

	r = vdisk_con_init(&queue->con);
	if (r)
		return r;

	r = vdisk_con_connect(&queue->con, disk->session->con.host,
			      disk->session->con.port);
	if (r)
		goto deinit_con;

	snprintf(queue->con.session_id, ARRAY_SIZE(queue->con.session_id), "%s",
		 disk->session->con.session_id);
	snprintf(queue->con.disk_handle, ARRAY_SIZE(queue->con.disk_handle),
		 "%s", disk->session->con.disk_handle);

	thread = kthread_create(vdisk_thread_routine, queue,
				"vdisk%d-queue-%d", disk->number, index);
	if (IS_ERR(thread)) {
		r = PTR_ERR(thread);
		goto close_con;
	}

	get_task_struct(thread);
	queue->thread = thread;
	wake_up_process(queue->thread);

	return 0;

close_con:
	vdisk_con_close(&queue->con);
deinit_con:
	vdisk_con_deinit(&queue->con);
	return r;
}

static void vdisk_renew_worker(struct work_struct *work)
{
	struct vdisk *disk;
	int r;


	disk = container_of(work, struct vdisk, renew_work);

	r = vdisk_con_renew(&disk->session->con, disk);
	TRACE("disk 0x%p renew r %d", disk, r);
}

static enum hrtimer_restart vdisk_renew_timer_callback(struct hrtimer *timer)
{
	struct vdisk *disk;

	disk = container_of(timer, struct vdisk, renew_timer);

	queue_work(disk->wq, &disk->renew_work);

	hrtimer_start(&disk->renew_timer,
		      ktime_add_ms(ktime_get(), VDISK_TIMEOUT_MS / 4),
		      HRTIMER_MODE_ABS);

	return HRTIMER_NORESTART;
}

static int vdisk_session_start_disk(struct vdisk_session *session,
				    char *name, u64 size, u64 disk_id,
				    char *disk_handle, unsigned char key[32])
{
	struct vdisk_global *glob = vdisk_get_global();
	struct vdisk *disk;
	struct gendisk *gdisk;
	int number;
	int r, i;

	TRACE("creating disk %s", name);

	if (size & 511 || (size % VDISK_CACHE_SIZE) != 0)
		return -EINVAL;
	if (ARRAY_SIZE(disk->key) != 32)
		return -EINVAL;

	number = -1;
	for (i = 0; i < VDISK_DISK_NUMBER_MAX; i++) {
		if (test_and_set_bit(i, glob->disk_numbers) == 0) {
			number = i;
			break;
		}
	}

	if (number < 0)
		return -EINVAL;

	disk = vdisk_kzalloc(sizeof(*disk), GFP_KERNEL);
	if (!disk) {
		r = -ENOMEM;
		goto free_number;
	}
	disk->session = session;
	disk->number = number;
	disk->size = size;
	disk->disk_id = disk_id;
	memcpy(disk->key, key, sizeof(disk->key));

	snprintf(disk->name, ARRAY_SIZE(disk->name),
		 "%s", name);
	snprintf(disk->disk_handle, ARRAY_SIZE(disk->disk_handle),
		"%s", disk_handle);

	hrtimer_init(&disk->renew_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	disk->renew_timer.function = vdisk_renew_timer_callback;
	INIT_WORK(&disk->renew_work, vdisk_renew_worker);
	disk->wq = alloc_workqueue("vdisk-wq", WQ_MEM_RECLAIM, 0);
	if (!disk->wq) {
		r = -ENOMEM;
		goto free_disk;
	}

	r = vdisk_cache_init(disk);
	if (r)
		goto free_wq;

	for (i = 0; i < ARRAY_SIZE(disk->queue); i++) {
		r = vdisk_queue_init(disk, i);
		if (r) {
			int j;

			for (j = 0; j < i; j++)
				vdisk_queue_deinit(disk, j);

			goto free_cache;
		}
	}

	disk->req_queue = blk_alloc_queue(GFP_KERNEL);
	if (!disk->req_queue) {
		r = -ENOMEM;
		goto free_queues;
	}

	blk_queue_make_request(disk->req_queue, vdisk_make_request);
	blk_queue_max_hw_sectors(disk->req_queue, 1024);
	blk_queue_bounce_limit(disk->req_queue, BLK_BOUNCE_ANY);

	disk->req_queue->limits.discard_granularity = PAGE_SIZE;
	disk->req_queue->limits.max_discard_sectors = UINT_MAX;
	disk->req_queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, disk->req_queue);

	gdisk = alloc_disk(1);
	if (!gdisk) {
		r = -ENOMEM;
		goto free_queue;
	}

	gdisk->major = glob->major;
	gdisk->first_minor = disk->number;
	gdisk->fops = &vdisk_fops;
	gdisk->private_data = disk;
	gdisk->queue = disk->req_queue;
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

	hrtimer_start(&disk->renew_timer, ktime_add_ms(ktime_get(),
		      (VDISK_TIMEOUT_MS) / 4), HRTIMER_MODE_ABS);

	return 0;

free_gdisk:
	put_disk(gdisk);
free_queue:
	blk_cleanup_queue(disk->req_queue);
free_queues:
	for (i = 0; i < ARRAY_SIZE(disk->queue); i++)
		vdisk_queue_deinit(disk, i);
free_cache:
	vdisk_cache_deinit(disk);
free_wq:
	destroy_workqueue(disk->wq);
free_disk:
	vdisk_kfree(disk);
free_number:
	clear_bit(number, glob->disk_numbers);
	return r;
}

int vdisk_session_create_disk(struct vdisk_session *session,
			      char *name, u64 size, unsigned char key[32])
{
	u64 disk_id;
	char *disk_handle;
	int r;

	r = vdisk_con_create_disk(&session->con, name, size, &disk_id);
	if (r) {
		TRACE_ERR(r, "create disk failed");
		return r;
	}

	TRACE("disk name %s disk_id %llu size %llu created",
	      name, disk_id, size);

	r = vdisk_con_open_disk(&session->con, name, &disk_id,
				&disk_handle, &size);
	if (r) {
		TRACE_ERR(r, "can't open disk");
		goto delete_disk;
	}

	TRACE("disk %s open r %d", name, r);

	r = vdisk_session_start_disk(session, name, size, disk_id,
				     disk_handle, key);
	if (r) {
		TRACE_ERR(r, "can't start disk");
		goto close_disk;
	}

	TRACE("disk %s start r %d", name, r);

	vdisk_kfree(disk_handle);
	return 0;

close_disk:
	vdisk_con_close_disk(&session->con, disk_id, disk_handle);
	vdisk_kfree(disk_handle);
delete_disk:
	vdisk_con_delete_disk(&session->con, name);
	return r;
}

int vdisk_session_delete_disk(struct vdisk_session *session, char *name)
{
	struct vdisk *curr, *tmp;
	int r;

	TRACE("deleting disk %s", name);

	r = -ENOTTY;
	down_write(&session->rw_sem);
	list_for_each_entry_safe(curr, tmp, &session->disk_list, list) {
		if (strncmp(curr->name, name, strlen(curr->name) + 1) == 0) {
			list_del_init(&curr->list);
			vdisk_release(curr);
			r = vdisk_con_delete_disk(&session->con, name);
			break;
		}
	}
	up_write(&session->rw_sem);

	return r;
}

int vdisk_session_open_disk(struct vdisk_session *session, char *name,
			    unsigned char key[32])
{
	u64 disk_id, size;
	char *disk_handle;
	int r;

	r = vdisk_con_open_disk(&session->con, name, &disk_id,
				&disk_handle, &size);
	if (r) {
		TRACE_ERR(r, "cant open disk");
		return r;
	}

	TRACE("session 0x%p open disk name %s r %d",
	      session, name, r);

	r = vdisk_session_start_disk(session, name, size, disk_id,
				     disk_handle, key);
	if (r) {
		TRACE_ERR(r, "can't start disk");
		goto close_disk;
	}

	TRACE("session 0x%p start disk %llu r %d", session, disk_id, r);

	r = 0;
	goto free_handle;

close_disk:
	vdisk_con_close_disk(&session->con, disk_id, disk_handle);
free_handle:
	vdisk_kfree(disk_handle);
	return r;
}

int vdisk_session_close_disk(struct vdisk_session *session, char *name)
{
	struct vdisk *curr, *tmp;
	int r;

	TRACE("closing disk %s", name);

	r = -ENOTTY;
	down_write(&session->rw_sem);
	list_for_each_entry_safe(curr, tmp, &session->disk_list, list) {
		if (strncmp(curr->name, name, strlen(curr->name) + 1) == 0) {
			list_del_init(&curr->list);
			r = vdisk_release(curr);
			TRACE("disk 0x%p name %s closed r %d",
			      curr, name, r);
			break;
		}
	}
	up_write(&session->rw_sem);

	return r;
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

	session = vdisk_kzalloc(sizeof(*session), GFP_KERNEL);
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
	vdisk_kfree(session);
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

int vdisk_encrypt(struct vdisk *disk, void *input,
		  u32 len, void *output, void *iv, u32 iv_len)
{
	mbedtls_aes_context aes;
	unsigned char local_iv[16];
	int r;

	if (iv_len != sizeof(local_iv))
		return -EINVAL;

	mbedtls_aes_init(&aes);
	r = mbedtls_aes_setkey_enc(&aes, disk->key, sizeof(disk->key) * 8);
	if (r)
		return r;

	get_random_bytes(&local_iv, sizeof(local_iv));

	memcpy(iv, local_iv, sizeof(local_iv));

	r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len,
				  local_iv, input, output);

	mbedtls_aes_free(&aes);

	return r;
}

int vdisk_decrypt(struct vdisk *disk, void *input,
		  u32 len, void *output, void *iv, u32 iv_len)
{
	mbedtls_aes_context aes;
	unsigned char local_iv[16];
	int r;

	if (iv_len != sizeof(local_iv))
		return -EINVAL;

	memcpy(local_iv, iv, sizeof(local_iv));

	mbedtls_aes_init(&aes);
	r = mbedtls_aes_setkey_dec(&aes, disk->key, sizeof(disk->key) * 8);
	if (r)
		return r;

	r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len,
				  local_iv, input, output);

	mbedtls_aes_free(&aes);

	return r;
}

void *vdisk_kzalloc(size_t size, gfp_t flags)
{
#ifdef __MALLOC_CHECKER__
	void *ptr;

	ptr = vdisk_kmalloc(size, flags);
	if (ptr)
		memset(ptr, 0, size);

	return ptr;
#else
	return kzalloc(size, flags);
#endif
}

void *vdisk_kcalloc(size_t n, size_t size, gfp_t flags)
{
#ifdef __MALLOC_CHECKER__
	void *ptr;

	ptr = vdisk_kmalloc(n * size, flags);
	if (ptr)
		memset(ptr, 0, n * size);

	return ptr;
#else
	return kcalloc(n, size, flags);
#endif
}

void *vdisk_kmalloc(size_t size, gfp_t flags)
{
#ifdef __MALLOC_CHECKER__
	return malloc_checker_kmalloc(size, flags);
#else
	return kmalloc(size, flags);
#endif
}

void vdisk_kfree(void *ptr)
{
#ifdef __MALLOC_CHECKER__
	malloc_checker_kfree(ptr);
#else
	kfree(ptr);
#endif
}

static int __init vdisk_init(void)
{
	struct vdisk_global *glob = vdisk_get_global();
	int r;

#ifdef __MALLOC_CHECKER__
	r = malloc_checker_init();
	if (r) {
		PRINTK("malloc checker init r %d", r);
		return r;
	}
#endif

	mbedtls_setup_callbacks();

	r = vdisk_init_global(glob);
	if (r) {
#ifdef __MALLOC_CHECKER__
		malloc_checker_deinit();
#endif
		pr_err("vdisk: cant init global, r %d", r);
		return r;
	}

	PRINTK("inited, vdisk_init=0x%p global=0x%p", vdisk_init, glob);
	return 0;
}

static void __exit vdisk_exit(void)
{
	struct vdisk_global *glob = vdisk_get_global();

	vdisk_deinit_global(glob);

#ifdef __MALLOC_CHECKER__
	malloc_checker_deinit();
#endif

	PRINTK("exited");
}

module_init(vdisk_init)
module_exit(vdisk_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("Virtual disk");
MODULE_LICENSE("GPL");
