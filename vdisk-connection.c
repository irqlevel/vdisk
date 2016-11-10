#include "vdisk-connection.h"
#include "ksocket.h"

static struct vdisk_req_header *vdisk_req_create(u32 type, u32 len)
{
	struct vdisk_req_header *req;
	u32 total_len;

	total_len = sizeof(*req) + len;
	req = kmalloc(total_len, GFP_KERNEL);
	if (!req)
		return NULL;

	req->magic = cpu_to_le32(VDISK_REQ_MAGIC);
	req->len = cpu_to_le32(total_len);
	req->type = cpu_to_le32(type);
	return req;
}

int vdisk_con_init(struct vdisk_connection *con)
{
	memset(con, 0, sizeof(*con));
	init_rwsem(&con->rw_sem);
	return 0;
}

void vdisk_con_deinit(struct vdisk_connection *con)
{
	vdisk_con_close(con);
}

int vdisk_con_connect(struct vdisk_connection *con, u32 ip, u16 port)
{
	int r;
	struct socket *sock;

	down_write(&con->rw_sem);
	if (con->sock) {
		r = -EEXIST;
		goto unlock;
	}

	r = ksock_connect(&sock, 0, 0, ip, port);
	if (r)
		goto unlock;

	con->sock = sock;
	r = 0;

unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_close(struct vdisk_connection *con)
{
	down_write(&con->rw_sem);
	if (con->sock) {
		ksock_release(con->sock);
		con->sock = NULL;
	}
	up_write(&con->rw_sem);
	return 0;
}

static int vdisk_send_req(struct socket *sock, struct vdisk_req_header *req)
{
	u32 wrote;
	int r;

	r = ksock_write(sock, req, le32_to_cpu(req->len), &wrote);
	if (r)
		return r;

	if (wrote != le32_to_cpu(req->len))
		return -EIO;

	return 0;
}

static int vdisk_recv_resp(struct socket *sock, u32 type, u32 len, void **body)
{
	struct vdisk_resp_header header;
	u32 read;
	u32 llen, ltype;
	void *lbody;
	int r;

	r = ksock_read(sock, &header, sizeof(header), &read);
	if (r)
		return r;

	if (read != sizeof(header))
		return -EIO;

	if (le32_to_cpu(header.magic) != VDISK_RESP_MAGIC)
		return -EINVAL;

	ltype = le32_to_cpu(header.type);
	llen = le32_to_cpu(header.len);
	if (llen > VDISK_BODY_MAX)
		return -EINVAL;
	if (llen <= sizeof(header))
		return -EINVAL;
	llen -= sizeof(header);
	if (type != ltype || len != llen)
		return -EINVAL;

	lbody = kmalloc(llen, GFP_KERNEL);
	if (!lbody)
		return -ENOMEM;

	r = ksock_read(sock, lbody, llen, &read);
	if (r)
		goto free_body;

	if (read != llen) {
		r = -ENOMEM;
		goto free_body;
	}

	*body = body;

	return 0;
free_body:
	kfree(lbody);
	return r;
}

int vdisk_login(struct vdisk_connection *con, u32 ip, u16 port,
		char *user_name, char *password)
{
	int r;
	struct vdisk_req_header *req;
	struct vdisk_req_login *req_body;
	struct vdisk_resp_login *resp;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_LOGIN, sizeof(*req_body));
	if (!req) {
		r = -ENOMEM;
		goto unlock;
	}

	req_body = (struct vdisk_req_login *)(req + 1);
	snprintf(req_body->user_name, ARRAY_SIZE(req_body->user_name),
		 "%s", user_name);
	snprintf(req_body->password, ARRAY_SIZE(req_body->password),
		 "%s", password);

	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_LOGIN,
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	r = resp->r;
	if (r)
		goto free_resp;

	snprintf(con->session_id, ARRAY_SIZE(con->session_id),
		 "%s", resp->session_id);
	r = 0;

free_resp:
	kfree(resp);
free_req:
	kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_logout(struct vdisk_connection *con)
{
	return -EINVAL;
}
