#ifndef __VDISK_CONNECTION_H__
#define __VDISK_CONNECTION_H__

#include <linux/kernel.h>
#include "vdisk.h"

struct vdisk_req_header *vdisk_req_create(u32 type, u32 len);

int vdisk_resp_parse(struct vdisk_resp_header *resp, u32 *type, u32 *len);

#endif
