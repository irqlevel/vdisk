#include "vdisk-connection.h"

struct vdisk_req_header *vdisk_req_create(u32 type, u32 len)
{
	struct vdisk_req_header *req;

	req = kmalloc(sizeof(*req) + len, GFP_KERNEL);
	if (!req)
		return NULL;

	req->magic = cpu_to_le32(VDISK_REQ_MAGIC);
	req->len = cpu_to_le32(len);
	req->type = cpu_to_le32(type);
	return req;
}

int vdisk_resp_parse(struct vdisk_resp_header *resp, u32 *type, u32 *len)
{
	if (le32_to_cpu(resp->magic) != VDISK_RESP_MAGIC)
		return -EINVAL;

	*type = le32_to_cpu(resp->type);
	*len = le32_to_cpu(resp->len);
	return 0;
}
