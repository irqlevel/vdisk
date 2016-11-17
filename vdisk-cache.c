#include "vdisk-cache.h"
#include "vdisk-trace-helpers.h"
#include "vdisk-connection.h"

static void vdisk_cache_get(struct vdisk_cache *cache)
{
	atomic_inc(&cache->ref_count);
}

static void vdisk_cache_release(struct vdisk_cache *cache)
{
	vdisk_kfree(cache->data);
	vdisk_kfree(cache);
}

static void vdisk_cache_put(struct vdisk_cache *cache, bool unpin)
{
	if (unpin) {
		WARN_ON(atomic_read(&cache->pin_count) < 1);
		atomic_dec(&cache->pin_count);
	}

	if (atomic_dec_and_test(&cache->ref_count))
		vdisk_cache_release(cache);
}

static struct vdisk_cache *vdisk_cache_alloc(struct vdisk *disk,
					     unsigned long index)
{
	struct vdisk_cache *cache;

	cache = vdisk_kzalloc(sizeof(*cache), GFP_NOIO);
	if (!cache)
		return NULL;

	cache->index = index;
	cache->disk = disk;
	INIT_LIST_HEAD(&cache->list);
	atomic_set(&cache->ref_count, 1);
	atomic_set(&cache->pin_count, 0);
	init_rwsem(&cache->rw_sem);

	cache->valid = false;
	cache->dirty = false;
	cache->data = vdisk_kmalloc(VDISK_CACHE_SIZE, GFP_NOIO);
	if (!cache->data)
		goto free_cache;

	return cache;

free_cache:
	vdisk_kfree(cache);
	return NULL;
}

static struct vdisk_cache *vdisk_cache_lookup(struct vdisk *disk,
					      unsigned long index,
					      bool pin)
{
	struct vdisk_cache *curr;
	unsigned long irq_flags;

	read_lock_irqsave(&disk->cache_lock, irq_flags);
	curr = radix_tree_lookup(&disk->cache_root, index);
	if (curr) {
		vdisk_cache_get(curr);
		if (pin)
			atomic_inc(&curr->pin_count);
	}
	read_unlock_irqrestore(&disk->cache_lock, irq_flags);

	return curr;
}

static struct vdisk_cache *__vdisk_cache_delete(struct vdisk *disk,
						unsigned long index)
{
	struct vdisk_cache *curr;

	curr = radix_tree_delete(&disk->cache_root, index);
	if (curr)
		disk->cache_entries--;
	return curr;
}

static struct vdisk_cache *vdisk_cache_insert(struct vdisk *disk,
					struct vdisk_cache *new,
					bool pin)
{
	struct vdisk_cache *curr;
	unsigned long irq_flags;

	if (radix_tree_preload(GFP_NOIO))
		return NULL;

	write_lock_irqsave(&disk->cache_lock, irq_flags);

	if (radix_tree_insert(&disk->cache_root, new->index, new))
		curr = radix_tree_lookup(&disk->cache_root, new->index);
	else {
		disk->cache_entries++;
		vdisk_cache_get(new);
		curr = new;
	}

	if (curr) {
		vdisk_cache_get(curr);
		if (pin)
			atomic_inc(&curr->pin_count);
	}
	write_unlock_irqrestore(&disk->cache_lock, irq_flags);

	return curr;
}

static int __vdisk_cache_read(struct vdisk_cache *cache,
				struct vdisk_connection *con)
{
	struct vdisk *disk;
	int r;

	disk = cache->disk;
	r = vdisk_con_copy_from(con, disk, cache->data,
				cache->index * VDISK_CACHE_SIZE,
				VDISK_CACHE_SIZE, 0);

	TRACE("cache read %llu r %d", cache->index, r);
	return r;
}

static int __vdisk_cache_write(struct vdisk_cache *cache,
				struct vdisk_connection *con,
				unsigned long rw)
{
	struct vdisk *disk;
	int r;

	if (WARN_ON(!cache->valid))
		return -EINVAL;
	if (WARN_ON(!cache->dirty))
		return -EINVAL;

	disk = cache->disk;
	r = vdisk_con_copy_to(con, disk, cache->data,
			      cache->index * VDISK_CACHE_SIZE,
			      VDISK_CACHE_SIZE, rw);
	if (!r)
		cache->dirty = false;

	TRACE("cache write %llu rw 0x%lx r %d", cache->index, rw, r);
	return r;
}

static bool __vdisk_cache_overflow(struct vdisk *disk)
{
	if (disk->cache_limit &&
	    (disk->cache_entries * VDISK_CACHE_SIZE) > disk->cache_limit)
		return true;
	return false;
}

static bool vdisk_cache_overflow(struct vdisk *disk)
{
	unsigned long irq_flags;
	bool overflow;

	read_lock_irqsave(&disk->cache_lock, irq_flags);
	overflow = __vdisk_cache_overflow(disk);
	read_unlock_irqrestore(&disk->cache_lock, irq_flags);

	return overflow;
}

static int __vdisk_cache_evict(struct vdisk *disk, unsigned long *index)
{
	struct vdisk_cache *batch[128];
	struct vdisk_cache *curr, *tmp, *deleted;
	unsigned long irq_flags;
	struct list_head list;
	int i, n, r;

	INIT_LIST_HEAD(&list);
	write_lock_irqsave(&disk->cache_lock, irq_flags);
	n = radix_tree_gang_lookup(&disk->cache_root,
		(void **)batch, *index, ARRAY_SIZE(batch));
	if (n) {
		*index = batch[n - 1]->index + 1;
		for (i = 0; i < n; i++) {
			curr = batch[i];
			if (atomic_read(&curr->pin_count) == 0) {
				vdisk_cache_get(curr);
				list_add_tail(&curr->list, &list);
			}
		}
	}
	write_unlock_irqrestore(&disk->cache_lock, irq_flags);
	if (!n)
		return -ENOTTY;

	list_for_each_entry_safe(curr, tmp, &list, list) {
		down_write(&curr->rw_sem);
		if (curr->dirty) {
			r = __vdisk_cache_write(curr, &disk->session->con, 0);
			if (r)
				TRACE_ERR(r, "can't write cache %llu r %d",
					  curr->index, r);
		}
		up_write(&curr->rw_sem);
	}

	write_lock_irqsave(&disk->cache_lock, irq_flags);
	list_for_each_entry_safe(curr, tmp, &list, list) {
		if (__vdisk_cache_overflow(disk) &&
		    atomic_read(&curr->pin_count) == 0 && !curr->dirty) {
			deleted = __vdisk_cache_delete(disk, curr->index);
			if (!WARN_ON(deleted != curr))
				vdisk_cache_put(curr, false);
		}
		list_del_init(&curr->list);
		vdisk_cache_put(curr, false);
	}
	write_unlock_irqrestore(&disk->cache_lock, irq_flags);
	return 0;
}

static void vdisk_cache_evict(struct vdisk *disk)
{
	unsigned long index;
	int i, r;

	TRACE("disk 0x%p cache evicting", disk);

	index = 0;
	for (i = 0; i < 20; i++) {
		if (!vdisk_cache_overflow(disk))
			break;

		r = __vdisk_cache_evict(disk, &index);
		if (!r)
			break;
	}

	atomic_set(&disk->cache_evicting, 0);
	TRACE("disk 0x%p cache evicted", disk);
}

static void vdisk_cache_evict_worker(struct work_struct *work)
{
	struct vdisk *disk;

	disk = container_of(work, struct vdisk, cache_evict_work);
	vdisk_cache_evict(disk);
}

void vdisk_cache_deinit(struct vdisk *disk)
{
	struct vdisk_cache *batch[16];
	struct vdisk_cache *curr, *tmp;
	unsigned long irq_flags;
	int i, n, r;

	hrtimer_cancel(&disk->cache_timer);

	drain_workqueue(disk->cache_wq);
	destroy_workqueue(disk->cache_wq);

	for (;;) {
		write_lock_irqsave(&disk->cache_lock, irq_flags);
		n = radix_tree_gang_lookup(&disk->cache_root,
			(void **)batch, 0, ARRAY_SIZE(batch));
		for (i = 0; i < n; i++) {
			curr = batch[i];
			WARN_ON(atomic_read(&curr->pin_count));
			tmp = __vdisk_cache_delete(disk, curr->index);
			WARN_ON(tmp != curr);
		}
		write_unlock_irqrestore(&disk->cache_lock, irq_flags);
		if (n == 0)
			break;

		for (i = 0; i < n; i++) {
			curr = batch[i];

			down_write(&curr->rw_sem);
			if (curr->dirty) {
				r = __vdisk_cache_write(curr,
					&disk->session->con, 0);
				if (r)
					TRACE_ERR(r, "can't write cache %llu",
						  curr->index);
			}
			up_write(&curr->rw_sem);
			vdisk_cache_put(curr, false);
		}
	}
}

static struct vdisk_cache *vdisk_cache_get_or_create(struct vdisk *disk,
						     unsigned long index,
						     bool pin)
{
	struct vdisk_cache *cache, *new;

	if (((index + 1) * VDISK_CACHE_SIZE) > disk->size)
		return NULL;

	cache = vdisk_cache_lookup(disk, index, pin);
	if (cache)
		return cache;

	new = vdisk_cache_alloc(disk, index);
	if (!new)
		return NULL;

	cache = vdisk_cache_insert(disk, new, pin);
	vdisk_cache_put(new, false);
	return cache;
}

int vdisk_cache_discard(struct vdisk_queue *queue, sector_t sector, u32 len)
{
	struct vdisk *disk = queue->disk;
	u64 off;
	int r;

	off = sector << SECTOR_SHIFT;

	TRACE("disk 0x%p discard off %llu len %u", disk, off, len);

	r = vdisk_con_discard(&queue->con, disk, off, len);

	TRACE("disk 0x%p discard off %llu len %u r %d", disk, off, len, r);
	return r;
}

static int __vdisk_cache_copy_from(struct vdisk_cache *cache,
			struct vdisk_connection *con, u32 off, u32 len,
			void *buf)
{
	int r;
	bool valid;

	down_read(&cache->rw_sem);
	valid = cache->valid;
	if (valid) {
		memcpy(buf, (unsigned char *)cache->data + off, len);
		r = 0;
	}
	up_read(&cache->rw_sem);
	if (valid)
		return r;

	down_write(&cache->rw_sem);
	if (!cache->valid) {
		r = __vdisk_cache_read(cache, con);
		if (r) {
			TRACE_ERR(r, "can't read cache %llu", cache->index);
			goto unlock;
		}
		cache->valid = true;
	}

	memcpy(buf, (unsigned char *)cache->data + off, len);
	r = 0;

unlock:
	up_write(&cache->rw_sem);
	return r;
}

static int __vdisk_cache_copy_to(struct vdisk_cache *cache,
			struct vdisk_connection *con, u32 off, u32 len,
			void *buf, unsigned long rw)
{
	int r;

	down_write(&cache->rw_sem);
	if (!cache->valid) {
		r = __vdisk_cache_read(cache, con);
		if (r) {
			TRACE_ERR(r, "can't read cache %llu", cache->index);
			goto unlock;
		}
		cache->valid = true;
	}

	memcpy((unsigned char *)cache->data + off, buf, len);
	cache->dirty = true;
	r = 0;

	if ((rw & REQ_FLUSH) || (rw & REQ_FUA)) {
		r = __vdisk_cache_write(cache, con, rw);
		if (r)
			TRACE_ERR(r, "can't write cache %llu", cache->index);
	}

unlock:
	up_write(&cache->rw_sem);

	return r;
}

static void vdisk_cache_trim(struct vdisk *disk, bool async)
{
	if (vdisk_cache_overflow(disk) &&
	    atomic_cmpxchg(&disk->cache_evicting, 0, 1) == 0) {
		if (async)
			queue_work(disk->cache_wq, &disk->cache_evict_work);
		else
			vdisk_cache_evict(disk);
	}
}

int vdisk_cache_copy_from(struct vdisk_queue *queue, void *buf, u64 off,
			  u32 len, unsigned long rw)
{
	struct vdisk *disk;
	struct vdisk_cache *cache;
	u64 loff;
	u32 llen;
	int r;

	disk = queue->disk;
	TRACE("disk 0x%p off %llu len %u rw 0x%x", disk, off, len, rw);

	if ((off + len) > disk->size) {
		r = -EINVAL;
		TRACE_ERR(r, "read beyond disk off %llu len %u", off, len);
		return r;
	}

	loff = off;
	llen = len;
	while (llen) {
		u32 coff = loff % VDISK_CACHE_SIZE;
		u32 can = VDISK_CACHE_SIZE - coff;

		cache = vdisk_cache_get_or_create(disk,
					loff / VDISK_CACHE_SIZE, true);
		if (!cache) {
			r = -ENOMEM;
			goto out;
		}

		if (can > llen)
			can = llen;

		r = __vdisk_cache_copy_from(cache, &queue->con, coff, can,
					(unsigned char *)buf + len - llen);
		vdisk_cache_put(cache, true);
		if (r)
			goto out;

		llen -= can;
		loff += can;
	}

out:
	TRACE("disk 0x%p off %llu len %u rw 0x%x r %d",
	      disk, off, len, rw, r);
	vdisk_cache_trim(disk, false);
	return r;
}

int vdisk_cache_copy_to(struct vdisk_queue *queue, void *buf, u64 off,
			u32 len, unsigned long rw)
{
	struct vdisk *disk;
	struct vdisk_cache *cache;
	u64 loff;
	u32 llen;
	int r;

	disk = queue->disk;
	TRACE("disk 0x%p off %llu len %u rw 0x%x",
	      disk, off, len, rw);

	if ((off + len) > disk->size) {
		r = -EINVAL;
		TRACE_ERR(r, "write beyond disk off %llu len %u", off, len);
		return r;
	}

	loff = off;
	llen = len;
	while (llen) {
		u32 coff = loff % VDISK_CACHE_SIZE;
		u32 can = VDISK_CACHE_SIZE - coff;

		cache = vdisk_cache_get_or_create(disk,
					loff / VDISK_CACHE_SIZE, true);
		if (!cache) {
			r = -ENOMEM;
			goto out;
		}

		if (can > llen)
			can = llen;

		r = __vdisk_cache_copy_to(cache, &queue->con, coff, can,
					(unsigned char *)buf + len - llen,
					rw);
		vdisk_cache_put(cache, true);
		if (r)
			goto out;

		llen -= can;
		loff += can;
	}

out:
	TRACE("disk 0x%p off %llu len %u rw 0x%x r %d",
	      disk, off, len, rw, r);
	vdisk_cache_trim(disk, false);
	return r;
}

static enum hrtimer_restart vdisk_cache_timer_callback(struct hrtimer *timer)
{
	struct vdisk *disk;

	disk = container_of(timer, struct vdisk, cache_timer);

	TRACE("disk 0x%p cache timer", disk);

	vdisk_cache_trim(disk, true);

	hrtimer_start(&disk->cache_timer,
		      ktime_add_ms(ktime_get(), VDISK_CACHE_TIMER_PERIOD_MS),
		      HRTIMER_MODE_ABS);

	return HRTIMER_NORESTART;
}

int vdisk_cache_init(struct vdisk *disk)
{
	INIT_RADIX_TREE(&disk->cache_root, GFP_NOIO);
	INIT_WORK(&disk->cache_evict_work, vdisk_cache_evict_worker);

	disk->cache_limit = 1024 * 1024;

	hrtimer_init(&disk->cache_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	disk->cache_timer.function = vdisk_cache_timer_callback;

	atomic_set(&disk->cache_evicting, 0);
	disk->cache_wq = alloc_workqueue("vdisk-cache-wq",
					WQ_MEM_RECLAIM, 0);
	if (!disk->cache_wq)
		return -ENOMEM;

	hrtimer_start(&disk->cache_timer,
		      ktime_add_ms(ktime_get(), VDISK_CACHE_TIMER_PERIOD_MS),
		      HRTIMER_MODE_ABS);

	return 0;
}

void vdisk_cache_set_limit(struct vdisk *disk, u64 limit)
{
	unsigned long irq_flags;

	write_lock_irqsave(&disk->cache_lock, irq_flags);
	disk->cache_limit = limit;
	write_unlock_irqrestore(&disk->cache_lock, irq_flags);

	vdisk_cache_trim(disk, false);
}
