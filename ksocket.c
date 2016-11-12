#include "ksocket.h"
#include <linux/version.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/uaccess.h>
#include <linux/tcp.h>

u16 ksock_peer_port(struct socket *sock)
{
	return be16_to_cpu(sock->sk->sk_dport);
}

u16 ksock_self_port(struct socket *sock)
{
	return sock->sk->sk_num;
}

u32 ksock_peer_addr(struct socket *sock)
{
	return be32_to_cpu(sock->sk->sk_daddr);
}

u32 ksock_self_addr(struct socket *sock)
{
	return be32_to_cpu(sock->sk->sk_rcv_saddr);
}

int ksock_create(struct socket **sockp,
	__u32 local_ip, int local_port)
{
	struct sockaddr_in	localaddr;
	struct socket		*sock = NULL;
	int			error;
	int			option;
	mm_segment_t		oldmm = get_fs();

	error = sock_create(PF_INET, SOCK_STREAM, 0, &sock);
	if (error)
		goto out;


	set_fs(KERNEL_DS);
	option = 1;
	error = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	if (error)
		goto out_sock_release;

	if (local_ip != 0 || local_port != 0) {
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(local_port);
		localaddr.sin_addr.s_addr = (local_ip == 0) ?
			INADDR_ANY : htonl(local_ip);
		error = sock->ops->bind(sock, (struct sockaddr *)&localaddr,
				sizeof(localaddr));
		if (error == -EADDRINUSE)
			goto out_sock_release;

		if (error)
			goto out_sock_release;

	}
	*sockp = sock;
	return 0;

out_sock_release:
	sock_release(sock);
out:
	return error;
}

int ksock_set_nodelay(struct socket *sock, bool no_delay)
{
	int option;
	int error;
	mm_segment_t oldmm = get_fs();

	option = (no_delay) ? 1 : 0;

	set_fs(KERNEL_DS);
	error = sock_setsockopt(sock, SOL_TCP, TCP_NODELAY,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	return error;
}

int ksock_set_sendbufsize(struct socket *sock, int size)
{
	int option = size;
	int error;
	mm_segment_t oldmm = get_fs();

	set_fs(KERNEL_DS);
	error = sock_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	return error;
}

int ksock_set_rcvbufsize(struct socket *sock, int size)
{
	int option = size;
	int error;
	mm_segment_t oldmm = get_fs();

	set_fs(KERNEL_DS);
	error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		(char *)&option, sizeof(option));
	set_fs(oldmm);

	return error;
}

int ksock_connect(struct socket **sockp, __u32 local_ip, int local_port,
			__u32 peer_ip, int peer_port)
{
	struct sockaddr_in srvaddr;
	int error;
	struct socket *sock = NULL;

	error = ksock_create(&sock, local_ip, local_port);
	if (error)
		goto out;

	error = ksock_set_nodelay(sock, true);
	if (error)
		goto out_sock_release;

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(peer_port);
	srvaddr.sin_addr.s_addr = htonl(peer_ip);

	error = sock->ops->connect(sock, (struct sockaddr *)&srvaddr,
			sizeof(srvaddr), 0);
	if (error)
		goto out_sock_release;

	*sockp = sock;
	return 0;

out_sock_release:
	sock_release(sock);
out:
	return error;
}

void ksock_release(struct socket *sock)
{

	synchronize_rcu();
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}

int ksock_write_timeout(struct socket *sock, void *buffer, u32 nob,
	u64 ticks, u32 *pwrote)
{
	int error;
	u64 then, delta;
	struct timeval tv;
	u32 wrote = 0;
	mm_segment_t oldmm = get_fs();

	if (WARN_ON(nob <= 0))
		return -EINVAL;

	for (;;) {
		struct iovec iov = {
			.iov_base = buffer,
			.iov_len = nob
		};
		struct msghdr msg;

		memset(&msg, 0, sizeof(msg));
		msg.msg_flags = (ticks == 0) ? MSG_DONTWAIT : 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 18, 0)
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
#else
		iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, nob);
#endif
		tv = (struct timeval) {
			.tv_sec = ticks/HZ,
			.tv_usec = ((ticks % HZ) * 1000000)/HZ
		};

		set_fs(KERNEL_DS);
		error = sock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
					(char *)&tv, sizeof(tv));
		set_fs(oldmm);
		if (error)
			goto out;

		then = get_jiffies_64();
		set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
		error = sock_sendmsg(sock, &msg, nob);
#else
		error = sock_sendmsg(sock, &msg);
#endif
		set_fs(oldmm);
		delta = get_jiffies_64() - then;
		delta = (delta > ticks) ? ticks : delta;
		ticks -= delta;

		if (error < 0)
			goto out;

		if (error == 0) {
			error = -ECONNABORTED;
			goto out;
		}

		if (error > 0)
			wrote += error;

		buffer = (void *)((unsigned long)buffer + error);
		WARN_ON(error <= 0);
		WARN_ON(nob < error);
		nob -= error;
		if (nob == 0) {
			error = 0;
			goto out;
		}

		if (ticks == 0) {
			error = -EAGAIN;
			goto out;
		}
	}
out:
	if (pwrote)
		*pwrote = wrote;

	return error;
}

int ksock_read_timeout(struct socket *sock, void *buffer, u32 nob,
	u64 ticks, u32 *pread)
{
	int error;
	u64 then, delta;
	struct timeval tv;
	u32 read = 0;
	mm_segment_t oldmm = get_fs();

	if (WARN_ON(nob <= 0))
		return -EINVAL;

	for (;;) {
		struct iovec iov = {
			.iov_base = buffer,
			.iov_len = nob
		};

		struct msghdr msg;

		memset(&msg, 0, sizeof(msg));
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 18, 0)
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
#else
		iov_iter_init(&msg.msg_iter, READ, &iov, 1, nob);
#endif
		tv = (struct timeval) {
			.tv_sec = ticks/HZ,
			.tv_usec = ((ticks % HZ) * 1000000)/HZ
		};

		set_fs(KERNEL_DS);
		error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
					(char *)&tv, sizeof(tv));
		set_fs(oldmm);

		if (error)
			goto out;

		then = get_jiffies_64();
		set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 5)
		error = sock_recvmsg(sock, &msg, 0);
#else
		error = sock_recvmsg(sock, &msg, nob, 0);
#endif
		set_fs(oldmm);
		delta = (get_jiffies_64() - then);
		delta = (delta > ticks) ? ticks : delta;
		ticks -= delta;

		if (error < 0)
			goto out;

		if (error == 0) {
			error = -ECONNRESET;
			goto out;
		}

		if (error > 0)
			read += error;

		buffer = (void *)((unsigned long)buffer + error);
		WARN_ON(error <= 0);
		WARN_ON(nob < error);
		nob -= error;
		if (nob == 0) {
			error = 0;
			goto out;
		}

		if (ticks == 0) {
			error = -ETIMEDOUT;
			goto out;
		}
	}
out:
	if (pread)
		*pread = read;
	return error;
}

int ksock_read(struct socket *sock, void *buffer, u32 nob, u32 *pread)
{
	u32 read = 0, off = 0;
	int err = 0;

	while (off < nob) {
		err = ksock_read_timeout(sock, (char *)buffer + off,
				nob - off, U64_MAX, &read);
		off += read;
		if (err)
			break;
	}
	*pread = off;
	return err;
}


int ksock_write(struct socket *sock, void *buffer, u32 nob, u32 *pwrote)
{
	u32 wrote = 0, off = 0;
	int err = 0;

	while (off < nob) {
		err = ksock_write_timeout(sock, (char *)buffer + off,
				nob - off, U64_MAX, &wrote);
		off += wrote;
		if (err)
			break;
	}
	*pwrote = off;
	return err;
}

int ksock_listen(struct socket **sockp, __u32 local_ip, int local_port,
	int backlog)
{
	int error;
	struct socket *sock = NULL;

	error = ksock_create(&sock, local_ip, local_port);
	if (error)
		return error;

	error = sock->ops->listen(sock, backlog);
	if (error)
		goto out;

	*sockp = sock;
	return 0;
out:
	sock_release(sock);
	return error;
}

int ksock_accept(struct socket **newsockp, struct socket *sock)
{
	wait_queue_t wait;
	struct socket *newsock;
	int error;

	init_waitqueue_entry(&wait, current);
	error = sock_create_lite(PF_PACKET, sock->type, IPPROTO_TCP, &newsock);
	if (error)
		return error;

	newsock->ops = sock->ops;
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(sk_sleep(sock->sk), &wait);
	error = sock->ops->accept(sock, newsock, O_NONBLOCK);
	if (error == -EAGAIN) {
		schedule();
		error = sock->ops->accept(sock, newsock, O_NONBLOCK);
	}
	remove_wait_queue(sk_sleep(sock->sk), &wait);
	set_current_state(TASK_RUNNING);
	if (error)
		goto out;

	*newsockp = newsock;
	return 0;
out:
	sock_release(newsock);
	return error;
}

void ksock_abort_accept(struct socket *sock)
{
	wake_up_all(sk_sleep(sock->sk));
}

int ksock_ioctl(struct socket *sock, int cmd, unsigned long arg)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	err = sock->ops->ioctl(sock, cmd, arg);
	set_fs(oldfs);
	return err;
}
