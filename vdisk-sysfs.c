/*
 * Copyright (C) 2016 Andrey Smetanin <irqlevel@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "vdisk-sysfs.h"

struct vdisk_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct vdisk *, char *);
	ssize_t (*store)(struct vdisk *, const char *, size_t count);
};

static struct vdisk *vdisk_from_kobject(struct kobject *kobj)
{
	struct vdisk *ctx;

	ctx = container_of(kobj, struct vdisk, kobj_holder.kobj);
	if (ctx->releasing)
		return NULL;

	return ctx;
}

static ssize_t vdisk_attr_show(struct kobject *kobj, struct attribute *attr,
			       char *page)
{
	struct vdisk_sysfs_attr *vdisk_attr;
	struct vdisk *ctx;
	ssize_t ret;

	vdisk_attr = container_of(attr, struct vdisk_sysfs_attr, attr);
	if (!vdisk_attr->show)
		return -EIO;

	ctx = vdisk_from_kobject(kobj);
	if (!ctx)
		return -EINVAL;

	ret = vdisk_attr->show(ctx, page);

	return ret;
}

static ssize_t vdisk_attr_store(struct kobject *kobj, struct attribute *attr,
				const char *page, size_t count)
{
	struct vdisk_sysfs_attr *vdisk_attr;
	struct vdisk *ctx;
	ssize_t ret;

	vdisk_attr = container_of(attr, struct vdisk_sysfs_attr, attr);
	if (!vdisk_attr->store)
		return -EIO;

	ctx = vdisk_from_kobject(kobj);
	if (!ctx)
		return -EINVAL;

	ret = vdisk_attr->store(ctx, page, count);
	return ret;
}

static ssize_t vdisk_attr_iops_show(struct vdisk *ctx, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->iops[0], ctx->iops[1]);
	return strlen(buf);
}

static ssize_t vdisk_attr_bps_show(struct vdisk *ctx, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->bps[0], ctx->bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_attr_max_iops_show(struct vdisk *ctx,
					char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->max_iops[0], ctx->max_iops[1]);
	return strlen(buf);
}

static ssize_t vdisk_attr_max_bps_show(struct vdisk *ctx,
				       char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->max_bps[0], ctx->max_bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_attr_limit_bps_show(struct vdisk *ctx,
					 char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->limit_bps[0], ctx->limit_bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_attr_limit_iops_show(struct vdisk *ctx,
					  char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->limit_bps[0], ctx->limit_bps[1]);
	return strlen(buf);
}

static ssize_t vdisk_attr_limit_bps_store(struct vdisk *ctx,
					  const char *buf, size_t count)
{
	u64 limit_bps[2];
	int r;

	r = sscanf(buf, "%llu %llu", &limit_bps[0], &limit_bps[1]);
	if (r < 2)
		return -EINVAL;

	vdisk_set_bps_limits(ctx, limit_bps, ARRAY_SIZE(limit_bps));
	return count;
}

static ssize_t vdisk_attr_limit_iops_store(struct vdisk *ctx,
					   const char *buf, size_t count)
{
	u64 limit_iops[2];
	int r;

	r = sscanf(buf, "%llu %llu", &limit_iops[0], &limit_iops[1]);
	if (r < 2)
		return -EINVAL;

	vdisk_set_iops_limits(ctx, limit_iops, ARRAY_SIZE(limit_iops));
	return count;
}

static ssize_t vdisk_attr_entropy_show(struct vdisk *ctx, char *buf)
{
	snprintf(buf, PAGE_SIZE, "%llu %llu\n",
		 ctx->entropy[0], ctx->entropy[1]);
	return strlen(buf);
}

#define VDISK_ATTR_RO(_name) \
struct vdisk_sysfs_attr vdisk_attr_##_name = \
	__ATTR(_name, S_IRUGO, vdisk_attr_##_name##_show, NULL)

#define VDISK_ATTR_RW(_name) \
struct vdisk_sysfs_attr vdisk_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, vdisk_attr_##_name##_show, \
		vdisk_attr_##_name##_store)

static VDISK_ATTR_RO(iops);
static VDISK_ATTR_RO(bps);
static VDISK_ATTR_RO(max_iops);
static VDISK_ATTR_RO(max_bps);
static VDISK_ATTR_RW(limit_iops);
static VDISK_ATTR_RW(limit_bps);
static VDISK_ATTR_RO(entropy);

static struct attribute *vdisk_attrs[] = {
	&vdisk_attr_iops.attr,
	&vdisk_attr_bps.attr,
	&vdisk_attr_max_iops.attr,
	&vdisk_attr_max_bps.attr,
	&vdisk_attr_limit_iops.attr,
	&vdisk_attr_limit_bps.attr,
	&vdisk_attr_entropy.attr,
	NULL,
};

static const struct sysfs_ops vdisk_sysfs_ops = {
	.show	= vdisk_attr_show,
	.store	= vdisk_attr_store,
};

static void vdisk_kobject_release(struct kobject *kobj)
{
	complete(vdisk_get_completion_from_kobject(kobj));
}

static struct kobj_type vdisk_ktype = {
	.sysfs_ops	= &vdisk_sysfs_ops,
	.default_attrs	= vdisk_attrs,
	.release	= vdisk_kobject_release,
};

struct vdisk_sysfs_context {
	struct vdisk_kobject_holder root_kobj_holder;
	bool exiting;
};

static struct vdisk_sysfs_context vdisk_sysfs_ctx;

int vdisk_disk_sysfs_init(struct vdisk *disk)
{
	init_completion(&disk->kobj_holder.completion);
	return kobject_init_and_add(&disk->kobj_holder.kobj, &vdisk_ktype,
			&vdisk_sysfs_ctx.root_kobj_holder.kobj,
			"%d", disk->number);
}

void vdisk_disk_sysfs_exit(struct vdisk *ctx)
{
	struct kobject *kobj = &ctx->kobj_holder.kobj;

	kobject_put(kobj);
	wait_for_completion(vdisk_get_completion_from_kobject(kobj));
}

static ssize_t vdisk_root_attr_create_store(const char *buf, size_t count)
{
	u64 size;
	int number;
	int r;

	r = sscanf(buf, "%d %llu", &number, &size);
	if (r < 2)
		return -EINVAL;

	r = vdisk_create(number, size);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_root_attr_create_show(char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t vdisk_root_attr_delete_store(const char *buf, size_t count)
{
	int number;
	int r;

	r = sscanf(buf, "%d", &number);
	if (r < 1)
		return -EINVAL;

	r = vdisk_delete(number);
	if (r)
		return r;

	return count;
}

static ssize_t vdisk_root_attr_delete_show(char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

struct vdisk_root_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(char *);
	ssize_t (*store)(const char *, size_t count);
};

#define VDISK_ROOT_ATTR_RO(_name) \
struct vdisk_root_sysfs_attr vdisk_root_attr_##_name = \
	__ATTR(_name, S_IRUGO, vdisk_root_attr_##_name##_show, NULL)

#define VDISK_ROOT_ATTR_RW(_name) \
struct vdisk_root_sysfs_attr vdisk_root_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, vdisk_root_attr_##_name##_show, \
		vdisk_root_attr_##_name##_store)

static VDISK_ROOT_ATTR_RW(create);
static VDISK_ROOT_ATTR_RW(delete);

static struct attribute *vdisk_root_attrs[] = {
	&vdisk_root_attr_create.attr,
	&vdisk_root_attr_delete.attr,
	NULL,
};

static ssize_t vdisk_root_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct vdisk_root_sysfs_attr *vdisk_attr;
	ssize_t ret;

	vdisk_attr = container_of(attr, struct vdisk_root_sysfs_attr, attr);
	if (!vdisk_attr->show)
		return -EIO;
	if (vdisk_sysfs_ctx.exiting)
		return -EAGAIN;
	ret = vdisk_attr->show(page);

	return ret;
}

static ssize_t vdisk_root_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *page, size_t count)
{
	struct vdisk_root_sysfs_attr *vdisk_attr;
	ssize_t ret;

	vdisk_attr = container_of(attr, struct vdisk_root_sysfs_attr, attr);
	if (!vdisk_attr->store)
		return -EIO;
	if (vdisk_sysfs_ctx.exiting)
		return -EAGAIN;
	ret = vdisk_attr->store(page, count);
	return ret;
}

static const struct sysfs_ops vdisk_root_sysfs_ops = {
	.show	= vdisk_root_attr_show,
	.store	= vdisk_root_attr_store,
};

static struct kobj_type vdisk_root_ktype = {
	.sysfs_ops	= &vdisk_root_sysfs_ops,
	.default_attrs	= vdisk_root_attrs,
	.release	= vdisk_kobject_release,
};

int vdisk_sysfs_init(void)
{
	init_completion(&vdisk_sysfs_ctx.root_kobj_holder.completion);
	return kobject_init_and_add(&vdisk_sysfs_ctx.root_kobj_holder.kobj,
				    &vdisk_root_ktype, fs_kobj, "%s", "vdisk");
}

void vdisk_sysfs_exit(void)
{
	struct kobject *kobj = &vdisk_sysfs_ctx.root_kobj_holder.kobj;

	vdisk_sysfs_ctx.exiting = true;
	kobject_put(kobj);
	wait_for_completion(vdisk_get_completion_from_kobject(kobj));
}
