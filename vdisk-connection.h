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

int vdisk_con_disk_create(struct vdisk_connection *con, u64 size, u64 *disk_id);

int vdisk_con_disk_delete(struct vdisk_connection *con, u64 disk_id);

#endif
