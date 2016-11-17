#include "vdisk-connection.h"
#include "ksocket.h"
#include "vdisk-trace-helpers.h"

static const unsigned char ca_cert[] = {
	0x30, 0x82, 0x2, 0x7, 0x30, 0x82, 0x1, 0x8e, 0xa0, 0x3, 0x2,
	0x1, 0x2, 0x2, 0x9, 0x0, 0x82, 0x81, 0xd1, 0x10, 0xa5, 0xac,
	0xb6, 0xbd, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d,
	0x4, 0x3, 0x2, 0x30, 0x42, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3,
	0x55, 0x4, 0x6, 0x13, 0x2, 0x52, 0x55, 0x31, 0x15, 0x30, 0x13,
	0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xc, 0x44, 0x65, 0x66, 0x61,
	0x75, 0x6c, 0x74, 0x20, 0x43, 0x69, 0x74, 0x79, 0x31, 0x1c, 0x30,
	0x1a, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0x13, 0x44, 0x65, 0x66,
	0x61, 0x75, 0x6c, 0x74, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61, 0x6e,
	0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x1e, 0x17, 0xd, 0x31, 0x36,
	0x31, 0x31, 0x31, 0x35, 0x32, 0x30, 0x34, 0x30, 0x33, 0x31, 0x5a,
	0x17, 0xd, 0x32, 0x36, 0x31, 0x31, 0x31, 0x33, 0x32, 0x30, 0x34,
	0x30, 0x33, 0x31, 0x5a, 0x30, 0x42, 0x31, 0xb, 0x30, 0x9, 0x6,
	0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x52, 0x55, 0x31, 0x15, 0x30,
	0x13, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xc, 0x44, 0x65, 0x66,
	0x61, 0x75, 0x6c, 0x74, 0x20, 0x43, 0x69, 0x74, 0x79, 0x31, 0x1c,
	0x30, 0x1a, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0x13, 0x44, 0x65,
	0x66, 0x61, 0x75, 0x6c, 0x74, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61,
	0x6e, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x76, 0x30, 0x10, 0x6,
	0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x5, 0x2b,
	0x81, 0x4, 0x0, 0x22, 0x3, 0x62, 0x0, 0x4, 0x6c, 0x1, 0x21,
	0x8a, 0xa3, 0xf, 0xb5, 0x80, 0xbb, 0x6b, 0xa2, 0x1f, 0x80, 0x9d,
	0x2c, 0x22, 0x74, 0xb2, 0x4b, 0x63, 0xc, 0xe7, 0xc2, 0x3, 0x12,
	0xba, 0xa0, 0x2e, 0xf9, 0x55, 0x8c, 0xed, 0x5, 0x6a, 0x40, 0xf8,
	0x94, 0x6d, 0xe8, 0xc, 0x57, 0xbd, 0x32, 0xc4, 0xf5, 0xf2, 0xb9,
	0x12, 0x67, 0xfc, 0x69, 0x8d, 0xcb, 0x4d, 0x61, 0xb7, 0x29, 0x37,
	0x3e, 0xf5, 0x31, 0xa8, 0xde, 0xe6, 0xcc, 0x9d, 0x69, 0x32, 0xf1,
	0x88, 0x50, 0xb9, 0x34, 0x10, 0x6a, 0xda, 0x68, 0xee, 0xf4, 0xa5,
	0x1, 0x81, 0xd0, 0x35, 0xfd, 0x2b, 0xfa, 0xd, 0x3d, 0x3c, 0x39,
	0x56, 0x51, 0x36, 0x4a, 0x97, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d,
	0x6, 0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0x2e, 0x16,
	0x96, 0x42, 0xd8, 0x99, 0x55, 0x1a, 0x71, 0x23, 0x8c, 0x92, 0x75,
	0x0, 0xd9, 0x1c, 0x70, 0x74, 0xe9, 0x29, 0x30, 0x1f, 0x6, 0x3,
	0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x2e, 0x16,
	0x96, 0x42, 0xd8, 0x99, 0x55, 0x1a, 0x71, 0x23, 0x8c, 0x92, 0x75,
	0x0, 0xd9, 0x1c, 0x70, 0x74, 0xe9, 0x29, 0x30, 0xc, 0x6, 0x3,
	0x55, 0x1d, 0x13, 0x4, 0x5, 0x30, 0x3, 0x1, 0x1, 0xff, 0x30,
	0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2,
	0x3, 0x67, 0x0, 0x30, 0x64, 0x2, 0x30, 0x25, 0xa4, 0xdf, 0x2a,
	0x3a, 0xb0, 0xac, 0xc2, 0x96, 0x63, 0xb0, 0xbf, 0xf3, 0x6c, 0x59,
	0x54, 0x3, 0xce, 0x7e, 0xce, 0xf4, 0x6, 0x6d, 0x24, 0x51, 0xfa,
	0xc8, 0x0, 0x15, 0x52, 0xf3, 0x21, 0xc6, 0xf4, 0xac, 0x84, 0x51,
	0xe4, 0x53, 0x6f, 0x5f, 0x3c, 0xa1, 0x65, 0xa5, 0x81, 0xfe, 0xa3,
	0x2, 0x30, 0x44, 0x19, 0x7c, 0x2e, 0xff, 0x26, 0xf1, 0x2d, 0x8f,
	0xca, 0x5d, 0x1e, 0xff, 0xd5, 0xe3, 0x95, 0xc4, 0xb6, 0x42, 0x3c,
	0xb9, 0xc7, 0x94, 0x73, 0xee, 0x56, 0x72, 0x96, 0x4b, 0xa, 0x40,
	0x79, 0xee, 0x1e, 0xe5, 0x6e, 0xed, 0xa2, 0xa5, 0x3c, 0x73, 0x41,
	0x9a, 0xe4, 0x99, 0x94, 0xb1, 0x1f,
};

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
	mbedtls_x509_crt_init(&con->ssl_ca);
	return 0;
}

void vdisk_con_deinit(struct vdisk_connection *con)
{
	vdisk_con_close(con);

	mbedtls_x509_crt_free(&con->ssl_ca);
	mbedtls_entropy_free(&con->entropy);
	mbedtls_ssl_config_free(&con->ssl_conf);
	mbedtls_ssl_free(&con->ssl);
	mbedtls_ctr_drbg_free(&con->ctr_drbg);
}

static int __vdisk_con_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct vdisk_connection *con = ctx;
	int r;
	u32 wrote;

	r = ksock_write(con->sock, (void *)buf, len, &wrote);
	if (r)
		return r;

	TRACE_VERBOSE("sent len %d wrote %d r %d", len, wrote, r);

	return wrote;
}

static int __vdisk_con_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct vdisk_connection *con = ctx;
	int r;
	u32 read;

	r = ksock_read(con->sock, buf, len, &read);
	if (r)
		return r;

	TRACE_VERBOSE("recv len %d read %d r %d", len, read, r);

	return read;
}

static int vdisk_ssl_write(struct vdisk_connection *con,
			const unsigned char *buf, size_t len)
{
	int r;
	u32 wrote;

	wrote = 0;
	while (wrote < len) {
		r = mbedtls_ssl_write(&con->ssl, (unsigned char *)buf + wrote,
				      len - wrote);
		if (r < 0)
			return r;
		if (r == 0)
			return wrote;

		wrote += r;
	}

	return wrote;
}

static int vdisk_ssl_read(struct vdisk_connection *con, unsigned char *buf,
			size_t len)
{
	int r;
	u32 read;

	read = 0;
	while (read < len) {
		r = mbedtls_ssl_read(&con->ssl, (unsigned char *)buf + read,
				     len - read);
		if (r < 0)
			return r;
		if (r == 0)
			return read;

		read += r;
	}

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

	r = mbedtls_x509_crt_parse_der(&con->ssl_ca, ca_cert, sizeof(ca_cert));
	if (r) {
		TRACE_ERR(r, "ssl x509 crt can't parse der");
		r = -EIO;
		goto unlock;
	}

	mbedtls_ssl_conf_ca_chain(&con->ssl_conf, &con->ssl_ca, NULL);

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

	mbedtls_ssl_set_bio(&con->ssl, con, __vdisk_con_ssl_send,
			    __vdisk_con_ssl_recv, NULL);

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

static int __vdisk_send_req(struct vdisk_connection *con, u32 type, u32 len,
			    void *req)
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

	r = vdisk_ssl_write(con, req, len);
	if (r < 0)
		return r;
	wrote = r;

	if (wrote != len)
		return -EIO;

	return 0;
}

static int vdisk_send_req(struct vdisk_connection *con,
			  struct vdisk_req_header *req)
{
	u32 wrote;
	int r;

	r = vdisk_ssl_write(con, (const unsigned char *)req,
			      le32_to_cpu(req->len));
	if (r < 0)
		return r;
	wrote = r;

	if (wrote != le32_to_cpu(req->len))
		return -EIO;

	return 0;
}

static int __vdisk_recv_resp(struct vdisk_connection *con, u32 type, u32 len,
			     void *body)
{
	struct vdisk_resp_header header;
	u32 read;
	u32 llen, ltype, lresult;
	int r;

	r = vdisk_ssl_read(con, (unsigned char *)&header,
			     sizeof(header));
	if (r < 0)
		return r;
	read = r;

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

		r = vdisk_ssl_read(con, body, llen);
		if (r < 0)
			return r;
		read = r;
		if (read != llen) {
			r = -EIO;
			TRACE_ERR(r, "incomplete read %d llen %d", read, len);
			return r;
		}
	} else {
		/* in this case lresult should be != 0 */
		if (lresult == 0)
			lresult = -EINVAL;
	}

	return lresult;
}

static int vdisk_recv_resp(struct vdisk_connection *con, u32 type, u32 len,
			   void **body)
{
	void *lbody;
	int r;

	lbody = vdisk_kmalloc(len, GFP_KERNEL);
	if (!lbody)
		return -ENOMEM;

	r = __vdisk_recv_resp(con, type, len, lbody);
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

	r = vdisk_send_req(con, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con, VDISK_REQ_TYPE_LOGIN,
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
	r = vdisk_send_req(con, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con, VDISK_REQ_TYPE_LOGOUT,
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

	r = vdisk_send_req(con, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_CREATE,
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
	r = vdisk_send_req(con, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_DELETE,
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
	r = vdisk_send_req(con, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_OPEN,
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
	r = vdisk_send_req(con, req);
	if (r)
		goto free_req;

	r = vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_CLOSE,
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

int vdisk_con_copy_from(struct vdisk_connection *con, struct vdisk *disk,
			void *buf, u64 off, u32 len,
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
		 disk->disk_handle);
	req->disk_id = cpu_to_le64(disk->disk_id);
	req->offset = cpu_to_le64(off);
	req->size = cpu_to_le32(len);
	req->flags = cpu_to_le32(vdisk_io_flags_by_rw(rw));

	r = __vdisk_send_req(con, VDISK_REQ_TYPE_DISK_READ,
			     sizeof(*req_header) + sizeof(*req), req_header);
	if (r)
		goto unlock;

	r = __vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_READ,
			      sizeof(*resp), resp);
	if (r)
		goto unlock;

	r = vdisk_decrypt(disk, resp->data, len, buf, resp->iv,
			  sizeof(resp->iv));

	TRACE_VERBOSE("decrypt buf %4phN data %4phN iv %4phN off %llu",
		buf, resp->data, resp->iv, off);

unlock:
	up_write(&con->rw_sem);
	return r;
}

int vdisk_con_copy_to(struct vdisk_connection *con, struct vdisk *disk,
		      void *buf, u64 off, u32 len,
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
		 disk->disk_handle);
	req->disk_id = cpu_to_le64(disk->disk_id);
	req->offset = cpu_to_le64(off);
	req->size = cpu_to_le32(len);
	req->flags = cpu_to_le32(vdisk_io_flags_by_rw(rw));

	r = vdisk_encrypt(disk, buf, len, req->data, req->iv,
			  sizeof(req->iv));
	if (r)
		goto unlock;

	TRACE_VERBOSE("encrypt buf %4phN data %4phN iv %4phN off %llu",
		buf, req->data, req->iv, off);

	r = __vdisk_send_req(con, VDISK_REQ_TYPE_DISK_WRITE,
			     sizeof(*req_header) + sizeof(*req), req_header);
	if (r)
		goto unlock;

	r = __vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_WRITE,
			      sizeof(*resp), resp);
	if (r)
		goto unlock;
unlock:
	up_write(&con->rw_sem);

	return r;
}

int vdisk_con_discard(struct vdisk_connection *con, struct vdisk *disk,
		      u64 off, u32 len)
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
		 disk->disk_handle);
	req->disk_id = cpu_to_le64(disk->disk_id);
	req->offset = cpu_to_le64(off);
	req->size = cpu_to_le32(len);

	r = __vdisk_send_req(con, VDISK_REQ_TYPE_DISK_DISCARD,
			     sizeof(*req_header) + sizeof(*req), req_header);
	if (r)
		goto unlock;

	r = __vdisk_recv_resp(con, VDISK_REQ_TYPE_DISK_DISCARD,
			      sizeof(*resp), resp);
	if (r)
		goto unlock;
unlock:
	up_write(&con->rw_sem);

	return r;
}
