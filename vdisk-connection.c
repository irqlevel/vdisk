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

static int vdisk_recv_resp(struct socket *sock, u32 type, u32 len, u32 *result,
			   void **body)
{
	struct vdisk_resp_header header;
	u32 read;
	u32 llen, ltype, lresult;
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
	lresult = le32_to_cpu(header.result);
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

	*result = lresult;
	*body = lbody;

	return 0;
free_body:
	kfree(lbody);
	return r;
}

int vdisk_con_login(struct vdisk_connection *con,
		    char *user_name, char *password)
{
	struct vdisk_req_header *req;
	struct vdisk_req_login *login;
	struct vdisk_resp_login *resp;
	int r, result;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_TYPE_LOGIN, sizeof(*login));
	if (!req) {
		r = -ENOMEM;
		goto unlock;
	}

	login = (struct vdisk_req_login *)(req + 1);
	snprintf(login->user_name, ARRAY_SIZE(login->user_name),
		 "%s", user_name);
	snprintf(login->password, ARRAY_SIZE(login->password),
		 "%s", password);

	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_LOGIN,
			    sizeof(*resp), &result, (void **)&resp);
	if (r)
		goto free_req;

	r = result;
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

int vdisk_con_logout(struct vdisk_connection *con)
{
	struct vdisk_req_header *req;
	struct vdisk_req_logout *logout;
	struct vdisk_resp_logout *resp;
	int r;
	u32 result;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_TYPE_LOGOUT, sizeof(*logout));
	if (!req) {
		r = -ENOMEM;
		goto unlock;
	}

	logout = (struct vdisk_req_logout *)(req + 1);
	snprintf(logout->session_id, ARRAY_SIZE(logout->session_id),
		 "%s", con->session_id);
	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_LOGOUT,
			    sizeof(*resp), &result, (void **)&resp);
	if (r)
		goto free_req;

	r = result;
	if (r)
		goto free_resp;

	r = 0;

free_resp:
	kfree(resp);
free_req:
	kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_disk_create(struct vdisk_connection *con, u64 size, u64 *disk_id)
{
	struct vdisk_req_header *req;
	struct vdisk_req_disk_create *disk_create;
	struct vdisk_resp_disk_create *resp;
	int r;
	u32 result;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_TYPE_DISK_CREATE,
			       sizeof(*disk_create));
	if (!req) {
		r = -ENOMEM;
		goto unlock;
	}

	disk_create = (struct vdisk_req_disk_create *)(req + 1);
	snprintf(disk_create->session_id, ARRAY_SIZE(disk_create->session_id),
		 "%s", con->session_id);
	disk_create->size = cpu_to_le64(size);

	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_CREATE,
			    sizeof(*resp), &result, (void **)&resp);
	if (r)
		goto free_req;

	r = result;
	if (r)
		goto free_resp;

	*disk_id = le64_to_cpu(resp->disk_id);
	r = 0;

free_resp:
	kfree(resp);
free_req:
	kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_disk_delete(struct vdisk_connection *con, u64 disk_id)
{
	struct vdisk_req_header *req;
	struct vdisk_req_disk_delete *disk_delete;
	struct vdisk_resp_disk_delete *resp;
	int r;
	u32 result;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_TYPE_DISK_DELETE,
			       sizeof(*disk_delete));
	if (!req) {
		r = -ENOMEM;
		goto unlock;
	}

	disk_delete = (struct vdisk_req_disk_delete *)(req + 1);
	snprintf(disk_delete->session_id, ARRAY_SIZE(disk_delete->session_id),
		 "%s", con->session_id);
	disk_delete->disk_id = cpu_to_le64(disk_id);
	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_DELETE,
			    sizeof(*resp), &result, (void **)&resp);
	if (r)
		goto free_req;

	r = result;
	if (r)
		goto free_resp;

	r = 0;

free_resp:
	kfree(resp);
free_req:
	kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}
