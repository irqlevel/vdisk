#ifndef __VDISK_CONNECTION_H__
#define __VDISK_CONNECTION_H__

#include <linux/kernel.h>
#include "vdisk.h"

int vdisk_con_init(struct vdisk_connection *con);

void vdisk_con_deinit(struct vdisk_connection *con);

int vdisk_con_connect(struct vdisk_connection *con, u32 ip, u16 port);

int vdisk_con_close(struct vdisk_connection *con);

int vdisk_con_login(struct vdisk_connection *con,
		    char *user_name, char *password);

int vdisk_con_logout(struct vdisk_connection *con);

int vdisk_con_create_disk(struct vdisk_connection *con, u64 size, u64 *disk_id);

int vdisk_con_delete_disk(struct vdisk_connection *con, u64 disk_id);

int vdisk_con_open_disk(struct vdisk_connection *con, u64 disk_id,
			char **disk_handle, u64 *size);

int vdisk_con_close_disk(struct vdisk_connection *con, u64 disk_id,
			 char *disk_handle);

int vdisk_con_copy_from(struct vdisk_connection *con, u64 disk_id,
			char *disk_handle, void *buf, u64 off, u32 len,
			unsigned long rw);

int vdisk_con_copy_to(struct vdisk_connection *con, u64 disk_id,
		      char *disk_handle, void *buf, u64 off, u32 len,
		      unsigned long rw);

int vdisk_con_discard(struct vdisk_connection *con, u64 disk_id,
		      char *disk_handle, u64 off, u32 len);

#endif
