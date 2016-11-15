#include "vdisk-connection.h"
#include "ksocket.h"
#include "vdisk-trace-helpers.h"

static struct vdisk_req_header *vdisk_req_create(u32 type, u32 len)
{
	struct vdisk_req_header *req;
	u32 total_len;

	total_len = sizeof(*req) + len;
	req = vdisk_kmalloc(total_len, GFP_KERNEL);
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

	mbedtls_ctr_drbg_init(&con->ctr_drbg);
	mbedtls_ssl_init(&con->ssl);
	mbedtls_ssl_config_init(&con->ssl_conf);
	mbedtls_entropy_init(&con->entropy);
	mbedtls_x509_crt_init(&con->ca);
	return 0;
}

void vdisk_con_deinit(struct vdisk_connection *con)
{
	vdisk_con_close(con);

	mbedtls_x509_crt_free(&con->ca);
	mbedtls_entropy_free(&con->entropy);
	mbedtls_ssl_config_free(&con->ssl_conf);
	mbedtls_ssl_free(&con->ssl);
	mbedtls_ctr_drbg_free(&con->ctr_drbg);
}

static int vdisk_con_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct vdisk_connection *con = ctx;
	int r;
	u32 wrote;

	r = ksock_write(con->sock, (void *)buf, len, &wrote);
	if (r)
		return r;

	return wrote;
}

static int vdisk_con_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct vdisk_connection *con = ctx;
	int r;
	u32 read;

	r = ksock_read(con->sock, buf, len, &read);
	if (r)
		return r;

	return read;
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

	r = mbedtls_ctr_drbg_seed(&con->ctr_drbg, mbedtls_entropy_func,
		&con->entropy, "custom", strlen("custom"));
	if (r) {
		TRACE_ERR(r, "ctr drbg seed failed");
		r = -EIO;
		goto unlock;
	}

	r = mbedtls_ssl_config_defaults(&con->ssl_conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);

	if (r) {
		TRACE_ERR(r, "ssl config defaults failed");
		r = -EIO;
		goto unlock;
	}

	mbedtls_ssl_conf_rng(&con->ssl_conf, mbedtls_ctr_drbg_random,
			     &con->ctr_drbg);

	mbedtls_ssl_conf_authmode(&con->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);


	r = mbedtls_ssl_setup(&con->ssl, &con->ssl_conf);
	if (r) {
		TRACE_ERR(r, "ssl setup failed");
		r = -EIO;
		goto unlock;
	}

	r = ksock_connect(&sock, 0, 0, ip, port);
	if (r) {
		TRACE_ERR(r, "connect failed");
		goto unlock;
	}

	r = ksock_set_nodelay(sock, true);
	if (r) {
		TRACE_ERR(r, "set no delay failed");
		goto release_sock;
	}

	con->ip = ip;
	con->port = port;
	con->sock = sock;

	mbedtls_ssl_set_bio(&con->ssl, con, vdisk_con_ssl_send,
			    vdisk_con_ssl_recv, NULL);

	r = mbedtls_ssl_handshake(&con->ssl);
	if (r) {
		TRACE_ERR(r, "ssl handshake failed");
		r = -EIO;
		goto reset_con;
	}

	r = 0;
	goto unlock;

reset_con:
	con->sock = NULL;
	con->ip = 0;
	con->port = 0;
release_sock:
	ksock_release(sock);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_close(struct vdisk_connection *con)
{
	down_write(&con->rw_sem);
	if (con->sock) {
		mbedtls_ssl_close_notify(&con->ssl);
		ksock_release(con->sock);
		con->sock = NULL;
		con->ip = 0;
		con->port = 0;
	}
	up_write(&con->rw_sem);
	return 0;
}

static int __vdisk_send_req(struct socket *sock, u32 type, u32 len, void *req)
{
	struct vdisk_req_header *header;
	u32 wrote;
	int r;

	header = req;
	if (len < sizeof(*header))
		return -EINVAL;

	if (len > VDISK_BODY_MAX)
		return -EINVAL;

	header->magic = cpu_to_le32(VDISK_REQ_MAGIC);
	header->len = cpu_to_le32(len);
	header->type = cpu_to_le32(type);

	r = ksock_write(sock, req, len, &wrote);
	if (r)
		return r;

	if (wrote != len)
		return -EIO;

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

static int __vdisk_recv_resp(struct socket *sock, u32 type, u32 len, void *body)
{
	struct vdisk_resp_header header;
	u32 read;
	u32 llen, ltype, lresult;
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
	if (llen < sizeof(header))
		return -EINVAL;
	llen -= sizeof(header);
	if (type != ltype)
		return -EINVAL;
	if (llen != 0) {
		if (llen != len)
			return -EINVAL;

		r = ksock_read(sock, body, llen, &read);
		if (r)
			return r;

		if (read != llen)
			return -ENOMEM;
	} else {
		/* in this case lresult should be != 0 */
		if (lresult == 0)
			lresult = -EINVAL;
	}

	return lresult;
}

static int vdisk_recv_resp(struct socket *sock, u32 type, u32 len, void **body)
{
	void *lbody;
	int r;

	lbody = vdisk_kmalloc(len, GFP_KERNEL);
	if (!lbody)
		return -ENOMEM;

	r = __vdisk_recv_resp(sock, type, len, lbody);
	if (r) {
		vdisk_kfree(lbody);
		return r;
	}
	*body = lbody;
	return 0;
}

int vdisk_con_login(struct vdisk_connection *con,
		    char *user_name, char *password)
{
	struct vdisk_req_header *req;
	struct vdisk_req_login *login;
	struct vdisk_resp_login *resp;
	int r;

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
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	snprintf(con->session_id, ARRAY_SIZE(con->session_id),
		 "%s", resp->session_id);
	vdisk_kfree(resp);
free_req:
	vdisk_kfree(req);
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
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	vdisk_kfree(resp);
free_req:
	vdisk_kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_create_disk(struct vdisk_connection *con, u64 size, u64 *disk_id)
{
	struct vdisk_req_header *req;
	struct vdisk_req_disk_create *disk_create;
	struct vdisk_resp_disk_create *resp;
	int r;

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
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	*disk_id = le64_to_cpu(resp->disk_id);

	vdisk_kfree(resp);
free_req:
	vdisk_kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_delete_disk(struct vdisk_connection *con, u64 disk_id)
{
	struct vdisk_req_header *req;
	struct vdisk_req_disk_delete *disk_delete;
	struct vdisk_resp_disk_delete *resp;
	int r;

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
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	vdisk_kfree(resp);
free_req:
	vdisk_kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_open_disk(struct vdisk_connection *con, u64 disk_id,
			char **disk_handle, u64 *size)
{
	struct vdisk_req_header *req;
	struct vdisk_req_disk_open *disk_open;
	struct vdisk_resp_disk_open *resp;
	int r, count;
	char *ldisk_handle;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_TYPE_DISK_OPEN,
			       sizeof(*disk_open));
	if (!req) {
		r = -ENOMEM;
		TRACE_ERR(r, "can't create request");
		goto unlock;
	}

	disk_open = (struct vdisk_req_disk_open *)(req + 1);
	snprintf(disk_open->session_id, ARRAY_SIZE(disk_open->session_id),
		 "%s", con->session_id);
	disk_open->disk_id = cpu_to_le64(disk_id);
	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_OPEN,
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	resp->disk_handle[ARRAY_SIZE(resp->disk_handle) - 1] = '\0';
	count = strlen(resp->disk_handle) + 1;
	ldisk_handle = vdisk_kcalloc(count, sizeof(char), GFP_KERNEL);
	if (!ldisk_handle) {
		r = -ENOMEM;
		TRACE_ERR(r, "can't alloc disk handle");
		goto free_resp;
	}
	snprintf(ldisk_handle, count, "%s", resp->disk_handle);
	*disk_handle = ldisk_handle;
	*size = le64_to_cpu(resp->size);
	r = 0;

free_resp:
	vdisk_kfree(resp);
free_req:
	vdisk_kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;

}

int vdisk_con_close_disk(struct vdisk_connection *con, u64 disk_id,
			 char *disk_handle)
{
	struct vdisk_req_header *req;
	struct vdisk_req_disk_close *disk_close;
	struct vdisk_resp_disk_close *resp;
	int r;

	r = -ENOTTY;
	down_write(&con->rw_sem);
	if (!con->sock)
		goto unlock;

	req = vdisk_req_create(VDISK_REQ_TYPE_DISK_CLOSE,
			       sizeof(*disk_close));
	if (!req) {
		r = -ENOMEM;
		goto unlock;
	}

	disk_close = (struct vdisk_req_disk_close *)(req + 1);
	snprintf(disk_close->session_id, ARRAY_SIZE(disk_close->session_id),
		 "%s", con->session_id);
	snprintf(disk_close->disk_handle, ARRAY_SIZE(disk_close->disk_handle),
		"%s", disk_handle);

	disk_close->disk_id = cpu_to_le64(disk_id);
	r = vdisk_send_req(con->sock, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_CLOSE,
			    sizeof(*resp), (void **)&resp);
	if (r)
		goto free_req;

	vdisk_kfree(resp);
free_req:
	vdisk_kfree(req);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_copy_from(struct vdisk_connection *con, u64 disk_id,
			char *disk_handle, void *buf, u64 off, u32 len,
			unsigned long rw)
{
	struct vdisk_req_header *req_header = &con->read_req_header;
	struct vdisk_req_disk_read *req = &con->read_req;
	struct vdisk_resp_disk_read *resp = &con->read_resp;
	int r;

	if (WARN_ON(len > sizeof(resp->data)))
		return -E2BIG;

	down_write(&con->rw_sem);
	if (!con->sock) {
		r = -EAGAIN;
		goto unlock;
	}

	snprintf(req->session_id, ARRAY_SIZE(req->session_id), "%s",
		 con->session_id);
	snprintf(req->disk_handle, ARRAY_SIZE(req->disk_handle), "%s",
		 disk_handle);
	req->disk_id = cpu_to_le64(disk_id);
	req->offset = cpu_to_le64(off);
	req->size = cpu_to_le32(len);
	req->flags = cpu_to_le32(vdisk_io_flags_by_rw(rw));

	r = __vdisk_send_req(con->sock, VDISK_REQ_TYPE_DISK_READ,
			     sizeof(*req_header) + sizeof(*req), req_header);
	if (r)
		goto unlock;

	r = __vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_READ,
			      sizeof(*resp), resp);
	if (r)
		goto unlock;
	memcpy(buf, resp->data, len);
unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_copy_to(struct vdisk_connection *con, u64 disk_id,
		      char *disk_handle, void *buf, u64 off, u32 len,
		      unsigned long rw)
{
	struct vdisk_req_header *req_header = &con->write_req_header;
	struct vdisk_req_disk_write *req = &con->write_req;
	struct vdisk_resp_disk_write *resp = &con->write_resp;
	int r;

	if (WARN_ON(len > sizeof(req->data)))
		return -E2BIG;

	down_write(&con->rw_sem);
	if (!con->sock) {
		r = -EAGAIN;
		goto unlock;
	}

	snprintf(req->session_id, ARRAY_SIZE(req->session_id), "%s",
		 con->session_id);
	snprintf(req->disk_handle, ARRAY_SIZE(req->disk_handle), "%s",
		 disk_handle);
	req->disk_id = cpu_to_le64(disk_id);
	req->offset = cpu_to_le64(off);
	req->size = cpu_to_le32(len);
	req->flags = cpu_to_le32(vdisk_io_flags_by_rw(rw));

	memcpy(req->data, buf, len);

	r = __vdisk_send_req(con->sock, VDISK_REQ_TYPE_DISK_WRITE,
			     sizeof(*req_header) + sizeof(*req), req_header);
	if (r)
		goto unlock;

	r = __vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_WRITE,
			      sizeof(*resp), resp);
	if (r)
		goto unlock;
unlock:
	up_write(&con->rw_sem);

	return r;
}

int vdisk_con_discard(struct vdisk_connection *con, u64 disk_id,
		      char *disk_handle, u64 off, u32 len)
{
	struct vdisk_req_header *req_header = &con->discard_req_header;
	struct vdisk_req_disk_discard *req = &con->discard_req;
	struct vdisk_resp_disk_discard *resp = &con->discard_resp;
	int r;

	down_write(&con->rw_sem);
	if (!con->sock) {
		r = -EAGAIN;
		goto unlock;
	}

	snprintf(req->session_id, ARRAY_SIZE(req->session_id), "%s",
		 con->session_id);
	snprintf(req->disk_handle, ARRAY_SIZE(req->disk_handle), "%s",
		 disk_handle);
	req->disk_id = cpu_to_le64(disk_id);
	req->offset = cpu_to_le64(off);
	req->size = cpu_to_le32(len);

	r = __vdisk_send_req(con->sock, VDISK_REQ_TYPE_DISK_DISCARD,
			     sizeof(*req_header) + sizeof(*req), req_header);
	if (r)
		goto unlock;

	r = __vdisk_recv_resp(con->sock, VDISK_REQ_TYPE_DISK_DISCARD,
			      sizeof(*resp), resp);
	if (r)
		goto unlock;
unlock:
	up_write(&con->rw_sem);

	return r;
}
