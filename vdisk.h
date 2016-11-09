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

#define VDISK_REQ_MAGIC		0xCBDACBDA
#define VDISK_RESP_MAGIC	0xCBDACBDA

#define VDISK_REQ_LOGIN		1
#define VDISK_REQ_LOGOUT	2
#define VDISK_REQ_DISK_CREATE	3
#define VDISK_REQ_DISK_DELETE	4
#define VDISK_REQ_DISK_OPEN	5
#define VDISK_REQ_DISK_CLOSE	6
#define VDISK_REQ_DISK_IO	7

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
	__le32 padding;
};

#define VDISK_ID_SIZE 256

struct vdisk_req_login {
	char user_name[VDISK_ID_SIZE];
	char password[VDISK_ID_SIZE];
};

struct vdisk_resp {
	int r;
};

struct vdisk_resp_login {
	char session_id[VDISK_ID_SIZE];
	int r;
};

struct vdisk_req_logout {
	char session_id[VDISK_ID_SIZE];
};

struct vdisk_req_disk_create {
	char session_id[VDISK_ID_SIZE];
};

struct vdisk_req_disk_delete {
	char session_id[VDISK_ID_SIZE];
	char disk_id[VDISK_ID_SIZE];
};

struct vdisk_req_disk_open {
	char session_id[VDISK_ID_SIZE];
	char disk_id[VDISK_ID_SIZE];
};

struct vdisk_resp_disk_open {
	char disk_handle[VDISK_ID_SIZE];
	int r;
};

struct vdisk_req_disk_close {
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
};

struct vdisk_req_disk_io {
	char session_id[VDISK_ID_SIZE];
	char disk_handle[VDISK_ID_SIZE];
};

struct vdisk_resp_disk_io {
	int r;
};

struct vdisk_bio {
	struct list_head list;
	struct bio *bio;
};

struct vdisk {
	int number;
	struct request_queue *queue;
	struct gendisk *gdisk;
	struct list_head list;
	rwlock_t lock;
	wait_queue_head_t waitq;
	struct list_head req_list;
	struct vdisk_kobject_holder kobj_holder;
	struct task_struct *thread;
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

int vdisk_set_server(u32 ip, u16 port);

#endif
