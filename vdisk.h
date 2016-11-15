#ifndef __VDISK_H__
#define __VDISK_H__

#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/zlib.h>
#include <linux/net.h>
#include <linux/radix-tree.h>

#include "mbedtls-helpers.h"
#include "mbedtls/mbedtls/ssl.h"
#include "mbedtls/mbedtls/entropy.h"
#include "mbedtls/mbedtls/ctr_drbg.h"

#define VDISK_DISK_NUMBER_MAX 256
#define VDISK_SESSION_NUMBER_MAX 256
#define VDISK_BLOCK_DEV_NAME "vdisk"

#define VDISK_IO_FLUSH		0x1
#define VDISK_IO_FUA		0x2
#define VDISK_IO_DISCARD	0x4
#define VDISK_IO_READA		0x8

#define VDISK_REQ_MAGIC		0xCBDACBDA
#define VDISK_RESP_MAGIC	0xCBDACBDA

#define VDISK_REQ_TYPE_LOGIN		1
#define VDISK_REQ_TYPE_LOGOUT		2
#define VDISK_REQ_TYPE_DISK_CREATE	3
#define VDISK_REQ_TYPE_DISK_DELETE	4
#define VDISK_REQ_TYPE_DISK_OPEN	5
#define VDISK_REQ_TYPE_DISK_CLOSE	6
#define VDISK_REQ_TYPE_DISK_READ	7
#define VDISK_REQ_TYPE_DISK_WRITE	8
#define VDISK_REQ_TYPE_DISK_DISCARD	9

#define VDISK_BODY_MAX		65536

#define VDISK_ID_SIZE		256
#define VDISK_ID_SCANF_FMT	"%255s"

#define VDISK_CACHE_PAGES	4
#define VDISK_CACHE_SIZE	(VDISK_CACHE_PAGES * PAGE_SIZE)

#define VDISK_QUEUE_MAX		2

struct vdisk_kobject_holder {
	struct kobject kobj;
	struct completion completion;
	atomic_t deiniting;
};

static inline struct completion *vdisk_get_completion_from_kobject(
					struct kobject *kobj)
{
	return &container_of(kobj,
			     struct vdisk_kobject_holder, kobj)->completion;
}

struct vdisk_req_header {
	__le32 magic;
	__le32 type;
	__le32 len;
	__le32 padding;
};

struct vdisk_resp_header {
	__le32 magic;
	__le32 type;
	__le32 len;
	__le32 result;
};

struct vdisk_req_login {
	char user_name[VDISK_ID_SIZE];
	char password[VDISK_ID_SIZE];
};

struct vdisk_resp_login {
	char session_id[VDISK_ID_SIZE];
};

struct vdisk_req_logout {
	char session_id[VDISK_ID_SIZE];
};

struct vdisk_resp_logout {
	__le64 padding;
};

struct vdisk_req_disk_create {
	char session_id[VDISK_ID_SIZE];
	__le64 size;
};

struct vdisk_resp_disk_create {
	__le64 disk_id;
};

struct vdisk_req_disk_delete {
	char session_id[VDISK_ID_SIZE];
	__le64 disk_id;
};

struct vdisk_resp_disk_delete {
	__le64 padding;
};

struct vdisk_req_disk_open {
	char session_id[VDISK_ID_SIZE];
	__le64 disk_id;
};

struct vdisk_resp_disk_open {
	char disk_handle[VDISK_ID_SIZE];
	__le64 size;
};

struct vdisk_req_disk_close {
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
	__le64 disk_id;
};

struct vdisk_resp_disk_close {
	__le64 padding;
};

static inline u32 vdisk_io_flags_by_rw(unsigned long rw)
{
	u32 flags;

	flags = 0;
	if (rw & REQ_FLUSH)
		flags |= VDISK_IO_FLUSH;
	if (rw & REQ_FUA)
		flags |= VDISK_IO_FUA;
	if (rw & REQ_DISCARD)
		flags |= VDISK_IO_DISCARD;
	if (rw & REQ_RAHEAD)
		flags |= VDISK_IO_READA;

	return flags;
}

struct vdisk_req_disk_read {
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
	__le64 disk_id;
	__le64 offset;
	__le32 size;
	__le32 flags;
};

struct vdisk_resp_disk_read {
	char data[VDISK_CACHE_SIZE];
};

struct vdisk_req_disk_write {
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
	__le64 disk_id;
	__le64 offset;
	__le32 size;
	__le32 flags;
	char data[VDISK_CACHE_SIZE];
};

struct vdisk_resp_disk_write {
	__le64 padding;
};

struct vdisk_req_disk_discard {
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
	__le64 disk_id;
	__le64 offset;
	__le32 size;
};

struct vdisk_resp_disk_discard {
	__le64 padding;
};

struct vdisk_bio {
	struct list_head list;
	struct bio *bio;
};

struct vdisk_connection {
	struct rw_semaphore rw_sem;
	struct socket *sock;
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
	char user_name[VDISK_ID_SIZE];

	u32 ip;
	u16 port;

	struct vdisk_req_header read_req_header;
	struct vdisk_req_disk_read read_req;
	struct vdisk_resp_disk_read read_resp;

	struct vdisk_req_header write_req_header;
	struct vdisk_req_disk_write write_req;
	struct vdisk_resp_disk_write write_resp;

	struct vdisk_req_header discard_req_header;
	struct vdisk_req_disk_discard discard_req;
	struct vdisk_resp_disk_discard discard_resp;

	mbedtls_ssl_context ssl;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config config;
};

struct vdisk_session {
	int number;
	struct list_head list;
	struct list_head disk_list;
	struct rw_semaphore rw_sem;
	struct vdisk_connection con;
	struct vdisk_kobject_holder kobj_holder;
};

struct vdisk;

struct vdisk_queue {
	struct vdisk *disk;
	struct vdisk_connection con;
	wait_queue_head_t waitq;
	rwlock_t lock;
	struct list_head req_list;
	struct task_struct *thread;
	int index;
};

struct vdisk {
	int number;
	struct vdisk_session *session;
	struct request_queue *req_queue;
	struct gendisk *gdisk;
	struct list_head list;
	rwlock_t lock;
	struct vdisk_queue queue[VDISK_QUEUE_MAX];
	struct vdisk_kobject_holder kobj_holder;
	u64 bps[2];
	u64 iops[2];
	u64 max_bps[2];
	u64 max_iops[2];
	u64 limit_bps[2];
	u64 limit_iops[2];
	u64 entropy[2];
	u64 size;
	u64 disk_id;
	bool releasing;
	char disk_handle[VDISK_ID_SIZE];

	rwlock_t cache_lock;
	struct radix_tree_root cache_root;
	u64 cache_entries;
	u64 cache_limit;
	struct work_struct cache_evict_work;
	struct workqueue_struct *cache_wq;
	atomic_t cache_evicting;
};

struct vdisk_cache {
	struct vdisk *disk;
	struct list_head list;
	void *data;
	unsigned long index;
	atomic_t ref_count;
	struct rw_semaphore rw_sem;
	bool valid;
	bool dirty;
	atomic_t pin_count;
};

struct vdisk_global {
	DECLARE_BITMAP(disk_numbers, VDISK_DISK_NUMBER_MAX);
	DECLARE_BITMAP(session_numbers, VDISK_SESSION_NUMBER_MAX);
	struct list_head session_list;
	struct rw_semaphore rw_sem;
	struct vdisk_kobject_holder kobj_holder;
	int major;
};

void vdisk_disk_set_iops_limits(struct vdisk *disk, u64 *limit_iops, int len);

void vdisk_disk_set_bps_limits(struct vdisk *disk, u64 *limit_bps, int len);

int vdisk_session_create_disk(struct vdisk_session *session,
			      int number, u64 size);

int vdisk_session_open_disk(struct vdisk_session *session, int number,
			    u64 disk_id);

int vdisk_session_close_disk(struct vdisk_session *session, int number);

int vdisk_session_delete_disk(struct vdisk_session *session, int number);

int vdisk_session_connect(struct vdisk_session *session, u32 ip, u16 port);

int vdisk_session_disconnect(struct vdisk_session *session);

int vdisk_session_login(struct vdisk_session *session,
			char *user_name, char *password);

int vdisk_session_logout(struct vdisk_session *session);

int vdisk_global_create_session(struct vdisk_global *glob, int number);

int vdisk_global_delete_session(struct vdisk_global *glob, int number);

void *vdisk_kzalloc(size_t size, gfp_t flags);

void *vdisk_kcalloc(size_t n, size_t size, gfp_t flags);

void *vdisk_kmalloc(size_t size, gfp_t flags);

void vdisk_kfree(void *ptr);

#endif
