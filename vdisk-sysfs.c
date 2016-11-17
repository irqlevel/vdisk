#include "vdisk-sysfs.h"
#include "vdisk-cache.h"
#include "vdisk-helpers.h"

#define VDISK_DISK_ATTR_RO(_name) \
struct vdisk_disk_sysfs_attr vdisk_disk_attr_##_name = \
	__ATTR(_name, S_IRUGO, vdisk_disk_attr_##_name##_show, NULL)

#define VDISK_DISK_ATTR_RW(_name) \
struct vdisk_disk_sysfs_attr vdisk_disk_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, vdisk_disk_attr_##_name##_show, \
		vdisk_disk_attr_##_name##_store)

#define VDISK_SESSION_ATTR_RO(_name) \
struct vdisk_session_sysfs_attr vdisk_session_attr_##_name = \
	__ATTR(_name, S_IRUGO, vdisk_session_attr_##_name##_show, NULL)

#define VDISK_SESSION_ATTR_RW(_name) \
struct vdisk_session_sysfs_attr vdisk_session_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, vdisk_session_attr_##_name##_show, \
		vdisk_session_attr_##_name##_store)

#define VDISK_GLOBAL_ATTR_RO(_name) \
struct vdisk_global_sysfs_attr vdisk_global_attr_##_name = \
	__ATTR(_name, S_IRUGO, vdisk_global_attr_##_name##_show, NULL)

#define VDISK_GLOBAL_ATTR_RW(_name) \
struct vdisk_global_sysfs_attr vdisk_global_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, vdisk_global_attr_##_name##_show, \
		vdisk_global_attr_##_name##_store)

struct vdisk_disk_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct vdisk *, char *);
	ssize_t (*store)(struct vdisk *, const char *, size_t count);
};

struct vdisk_session_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct vdisk_session *, char *);
	ssize_t (*store)(struct vdisk_session *, const char *, size_t count);
};

struct vdisk_global_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct vdisk_global *, char *);
	ssize_t (*store)(struct vdisk_global *, const char *, size_t count);
};

static void vdisk_kobject_release(struct kobject *kobj)
{
	complete(vdisk_get_completion_from_kobject(kobj));
}

static struct vdisk *vdisk_disk_from_kobject(struct kobject *kobj)
{
	return container_of(kobj, struct vdisk, kobj_holder.kobj);
}

static struct vdisk_session *vdisk_session_from_kobject(struct kobject *kobj)
{
	return container_of(kobj, struct vdisk_session, kobj_holder.kobj);
}

static struct vdisk_global *vdisk_global_from_kobject(struct kobject *kobj)
{
	return container_of(kobj, struct vdisk_global, kobj_holder.kobj);
}

int vdisk_sysfs_init(struct vdisk_kobject_holder *holder, struct kobject *root,
		     struct kobj_type *ktype, const char *fmt, ...)
{
	char name[256];
	va_list args;

	ktype->release = vdisk_kobject_release;

	init_completion(&holder->completion);

	va_start(args, fmt);
	vsnprintf(name, ARRAY_SIZE(name), fmt, args);
	va_end(args);

	return kobject_init_and_add(&holder->kobj, ktype, root, "%s", name);
}

void vdisk_sysfs_deinit(struct vdisk_kobject_holder *holder)
{
	struct kobject *kobj = &holder->kobj;

	if (atomic_cmpxchg(&holder->deiniting, 0, 1) == 0) {
		kobject_put(kobj);
		wait_for_completion(vdisk_get_completion_from_kobject(kobj));
	}
}

static ssize_t vdisk_disk_attr_iops_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->iops[0], disk->iops[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_bps_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->bps[0], disk->bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_max_iops_show(struct vdisk *disk,
					char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->max_iops[0], disk->max_iops[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_max_bps_show(struct vdisk *disk,
				       char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->max_bps[0], disk->max_bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_limit_bps_show(struct vdisk *disk,
					 char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->limit_bps[0], disk->limit_bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_limit_iops_show(struct vdisk *disk,
					  char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->limit_bps[0], disk->limit_bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_limit_bps_store(struct vdisk *disk,
					  const char *buf, size_t count)
{
	u64 limit_bps[2];
	int r;

	r = sscanf(buf, "%llu %llu", &limit_bps[0], &limit_bps[1]);
	if (r < 2)
		return -EINVAL;

	vdisk_disk_set_bps_limits(disk, limit_bps, ARRAY_SIZE(limit_bps));
	return count;
}

static ssize_t vdisk_disk_attr_limit_iops_store(struct vdisk *disk,
					   const char *buf, size_t count)
{
	u64 limit_iops[2];
	int r;

	r = sscanf(buf, "%llu %llu", &limit_iops[0], &limit_iops[1]);
	if (r < 2)
		return -EINVAL;

	vdisk_disk_set_iops_limits(disk, limit_iops, ARRAY_SIZE(limit_iops));
	return count;
}

static ssize_t vdisk_disk_attr_entropy_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 disk->entropy[0], disk->entropy[1]);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_disk_id_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu\n", disk->disk_id);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_size_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu\n", disk->size);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_disk_handle_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%s\n", disk->disk_handle);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_cache_limit_store(struct vdisk *disk,
					   const char *buf, size_t count)
{
	u64 limit;
	int r;

	r = sscanf(buf, "%llu", &limit);
	if (r < 1)
		return -EINVAL;

	vdisk_cache_set_limit(disk, limit);

	return count;
}

static ssize_t vdisk_disk_attr_cache_limit_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu\n", disk->cache_limit);
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_cache_usage_show(struct vdisk *disk, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu\n",
		 disk->cache_entries * VDISK_CACHE_SIZE);
	return strlen(buf);
}

static ssize_t vdisk_session_attr_create_disk_store(struct vdisk_session *sess,
						const char *buf, size_t count)
{
	char key_buf[VDISK_ID_SIZE];
	unsigned char key[32];
	u64 size;
	int number;
	int r;

	r = sscanf(buf, "%d %llu "VDISK_ID_SCANF_FMT, &number, &size, key_buf);
	if (r < 3)
		return -EINVAL;

	key_buf[VDISK_ID_SIZE - 1] = '\0';

	r = vdisk_hex_to_bytes(key_buf, strlen(key_buf), key, ARRAY_SIZE(key));
	if (r)
		return r;

	r = vdisk_session_create_disk(sess, number, size, key);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_create_disk_show(struct vdisk_session *sess,
						   char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_session_attr_open_disk_store(struct vdisk_session *sess,
						  const char *buf, size_t count)
{
	char key_buf[VDISK_ID_SIZE];
	unsigned char key[32];
	u64 disk_number;
	int number;
	int r;

	r = sscanf(buf, "%d %llu "VDISK_ID_SCANF_FMT, &number,
		   &disk_number, key_buf);
	if (r < 3)
		return -EINVAL;

	key_buf[VDISK_ID_SIZE - 1] = '\0';

	r = vdisk_hex_to_bytes(key_buf, strlen(key_buf), key, ARRAY_SIZE(key));
	if (r)
		return r;

	r = vdisk_session_open_disk(sess, number, disk_number, key);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_open_disk_show(struct vdisk_session *sess,
						 char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_session_attr_close_disk_store(struct vdisk_session *sess,
						const char *buf, size_t count)
{
	int number;
	int r;

	r = sscanf(buf, "%d", &number);
	if (r < 1)
		return -EINVAL;

	r = vdisk_session_close_disk(sess, number);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_close_disk_show(struct vdisk_session *sess,
						  char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_session_attr_delete_disk_store(struct vdisk_session *sess,
						const char *buf, size_t count)
{
	int number;
	int r;

	r = sscanf(buf, "%d", &number);
	if (r < 1)
		return -EINVAL;

	r = vdisk_session_delete_disk(sess, number);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_delete_disk_show(struct vdisk_session *sess,
						   char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_session_attr_connect_store(struct vdisk_session *session,
						const char *buf, size_t count)
{
	unsigned int ip_part[4], port, ip;
	int r;
	int i;

	r = sscanf(buf, "%u.%u.%u.%u:%u",
		   &ip_part[3], &ip_part[2], &ip_part[1], &ip_part[0], &port);
	if (r < 5)
		return -EINVAL;

	if (port > 65535)
		return -EINVAL;

	ip = 0;
	for (i = 0; i < ARRAY_SIZE(ip_part); i++) {
		if (ip_part[i] > 255)
			return -EINVAL;

		ip += (ip_part[i] << (i * 8));
	}

	r = vdisk_session_connect(session, (u32)ip, (u16)port);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_connect_show(struct vdisk_session *session,
						char *buf)
{
	unsigned char ip_part[4];
	int i;
	u32 ip;
	u16 port;

	down_read(&session->con.rw_sem);
	ip = session->con.ip;
	port = session->con.port;
	up_read(&session->con.rw_sem);

	for (i = 0; i < ARRAY_SIZE(ip_part); i++)
		ip_part[i] = (ip >> (i * 8)) & 0xFF;

	snprintf(buf, PAGE_SIZE, "%u.%u.%u.%u:%u\n",
		ip_part[3], ip_part[2], ip_part[1],
		ip_part[0], session->con.port);

	return strlen(buf);
}

static ssize_t vdisk_session_attr_disconnect_store(struct vdisk_session *sess,
						const char *buf, size_t count)
{
	int r;

	r = vdisk_session_disconnect(sess);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_disconnect_show(struct vdisk_session *session,
						char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");

	return strlen(buf);
}

static ssize_t vdisk_session_attr_login_store(struct vdisk_session *session,
					      const char *buf, size_t count)
{
	char user_name[VDISK_ID_SIZE], password[VDISK_ID_SIZE];
	int r;

	r = sscanf(buf, VDISK_ID_SCANF_FMT" "VDISK_ID_SCANF_FMT,
		   user_name, password);
	if (r < 2)
		return -EINVAL;

	user_name[VDISK_ID_SIZE - 1] = '\0';
	password[VDISK_ID_SIZE - 1] = '\0';

	r = vdisk_session_login(session, user_name, password);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_login_show(struct vdisk_session *session,
					     char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");

	return strlen(buf);
}

static ssize_t vdisk_session_attr_logout_store(struct vdisk_session *session,
					      const char *buf, size_t count)
{
	int r;

	r = vdisk_session_logout(session);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_session_attr_logout_show(struct vdisk_session *session,
					     char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");

	return strlen(buf);
}

static ssize_t vdisk_session_attr_session_id_show(struct vdisk_session *session,
					     char *buf)
{
	snprintf(buf, PAGE_SIZE, "%s\n", session->con.session_id);

	return strlen(buf);
}


static ssize_t vdisk_global_attr_create_session_store(struct vdisk_global *glob,
			const char *buf, size_t count)
{
	int number;
	int r;

	r = sscanf(buf, "%d", &number);
	if (r < 1)
		return -EINVAL;

	r = vdisk_global_create_session(glob, number);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_global_attr_create_session_show(struct vdisk_global *glob,
						     char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_global_attr_delete_session_store(struct vdisk_global *glob,
						const char *buf, size_t count)
{
	int number;
	int r;

	r = sscanf(buf, "%d", &number);
	if (r < 1)
		return -EINVAL;

	r = vdisk_global_delete_session(glob, number);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_global_attr_delete_session_show(struct vdisk_global *glob,
						     char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_disk_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct vdisk_disk_sysfs_attr *vattr;
	struct vdisk *disk;

	vattr = container_of(attr, struct vdisk_disk_sysfs_attr, attr);
	if (!vattr->show)
		return -EIO;

	disk = vdisk_disk_from_kobject(kobj);
	if (!disk)
		return -EIO;

	return vattr->show(disk, page);
}

static ssize_t vdisk_disk_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *page, size_t count)
{
	struct vdisk_disk_sysfs_attr *vattr;
	struct vdisk *disk;

	vattr = container_of(attr, struct vdisk_disk_sysfs_attr, attr);
	if (!vattr->store)
		return -EIO;

	disk = vdisk_disk_from_kobject(kobj);
	if (!disk)
		return -EIO;

	return vattr->store(disk, page, count);
}

static ssize_t vdisk_session_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct vdisk_session_sysfs_attr *vattr;
	struct vdisk_session *session;

	vattr = container_of(attr, struct vdisk_session_sysfs_attr, attr);
	if (!vattr->show)
		return -EIO;

	session = vdisk_session_from_kobject(kobj);
	if (!session)
		return -EIO;

	return vattr->show(session, page);
}

static ssize_t vdisk_session_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *page, size_t count)
{
	struct vdisk_session_sysfs_attr *vattr;
	struct vdisk_session *session;

	vattr = container_of(attr, struct vdisk_session_sysfs_attr, attr);
	if (!vattr->store)
		return -EIO;

	session = vdisk_session_from_kobject(kobj);
	if (!session)
		return -EIO;

	return vattr->store(session, page, count);
}

static ssize_t vdisk_global_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct vdisk_global_sysfs_attr *vattr;
	struct vdisk_global *glob;

	vattr = container_of(attr, struct vdisk_global_sysfs_attr, attr);
	if (!vattr->show)
		return -EIO;

	glob = vdisk_global_from_kobject(kobj);
	if (!glob)
		return -EIO;

	return vattr->show(glob, page);
}

static ssize_t vdisk_global_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *page, size_t count)
{
	struct vdisk_global_sysfs_attr *vattr;
	struct vdisk_global *glob;

	vattr = container_of(attr, struct vdisk_global_sysfs_attr, attr);
	if (!vattr->store)
		return -EIO;

	glob = vdisk_global_from_kobject(kobj);
	if (!glob)
		return -EIO;

	return vattr->store(glob, page, count);
}

/* Disk attributes */

static VDISK_DISK_ATTR_RO(iops);
static VDISK_DISK_ATTR_RO(bps);
static VDISK_DISK_ATTR_RO(max_iops);
static VDISK_DISK_ATTR_RO(max_bps);
static VDISK_DISK_ATTR_RW(limit_iops);
static VDISK_DISK_ATTR_RW(limit_bps);
static VDISK_DISK_ATTR_RO(entropy);
static VDISK_DISK_ATTR_RO(disk_id);
static VDISK_DISK_ATTR_RO(size);
static VDISK_DISK_ATTR_RO(disk_handle);
static VDISK_DISK_ATTR_RW(cache_limit);
static VDISK_DISK_ATTR_RO(cache_usage);

static struct attribute *vdisk_disk_attrs[] = {
	&vdisk_disk_attr_iops.attr,
	&vdisk_disk_attr_bps.attr,
	&vdisk_disk_attr_max_iops.attr,
	&vdisk_disk_attr_max_bps.attr,
	&vdisk_disk_attr_limit_iops.attr,
	&vdisk_disk_attr_limit_bps.attr,
	&vdisk_disk_attr_entropy.attr,
	&vdisk_disk_attr_disk_id.attr,
	&vdisk_disk_attr_size.attr,
	&vdisk_disk_attr_disk_handle.attr,
	&vdisk_disk_attr_cache_limit.attr,
	&vdisk_disk_attr_cache_usage.attr,
	NULL,
};

static const struct sysfs_ops vdisk_disk_sysfs_ops = {
	.show	= vdisk_disk_attr_show,
	.store	= vdisk_disk_attr_store,
};

struct kobj_type vdisk_disk_ktype = {
	.sysfs_ops	= &vdisk_disk_sysfs_ops,
	.default_attrs	= vdisk_disk_attrs,
};

/* Session attributes */

static VDISK_SESSION_ATTR_RW(create_disk);
static VDISK_SESSION_ATTR_RW(delete_disk);
static VDISK_SESSION_ATTR_RW(open_disk);
static VDISK_SESSION_ATTR_RW(close_disk);
static VDISK_SESSION_ATTR_RW(connect);
static VDISK_SESSION_ATTR_RW(disconnect);
static VDISK_SESSION_ATTR_RW(login);
static VDISK_SESSION_ATTR_RW(logout);
static VDISK_SESSION_ATTR_RO(session_id);

static struct attribute *vdisk_session_attrs[] = {
	&vdisk_session_attr_create_disk.attr,
	&vdisk_session_attr_delete_disk.attr,
	&vdisk_session_attr_open_disk.attr,
	&vdisk_session_attr_close_disk.attr,
	&vdisk_session_attr_connect.attr,
	&vdisk_session_attr_disconnect.attr,
	&vdisk_session_attr_login.attr,
	&vdisk_session_attr_logout.attr,
	&vdisk_session_attr_session_id.attr,
	NULL,
};

static const struct sysfs_ops vdisk_session_sysfs_ops = {
	.show	= vdisk_session_attr_show,
	.store	= vdisk_session_attr_store,
};

struct kobj_type vdisk_session_ktype = {
	.sysfs_ops	= &vdisk_session_sysfs_ops,
	.default_attrs	= vdisk_session_attrs,
};

/* Global attributes */

static VDISK_GLOBAL_ATTR_RW(create_session);
static VDISK_GLOBAL_ATTR_RW(delete_session);

static struct attribute *vdisk_global_attrs[] = {
	&vdisk_global_attr_create_session.attr,
	&vdisk_global_attr_delete_session.attr,
	NULL,
};

static const struct sysfs_ops vdisk_global_sysfs_ops = {
	.show	= vdisk_global_attr_show,
	.store	= vdisk_global_attr_store,
};

struct kobj_type vdisk_global_ktype = {
	.sysfs_ops	= &vdisk_global_sysfs_ops,
	.default_attrs	= vdisk_global_attrs,
};
