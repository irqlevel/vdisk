#ifndef __VDISK_KSOCKET_H__
#define __VDISK_KSOCKET_H__

#include <linux/net.h>

u16 ksock_self_port(struct socket *sock);
u16 ksock_peer_port(struct socket *sock);
u32 ksock_peer_addr(struct socket *sock);
u32 ksock_self_addr(struct socket *sock);

int ksock_create(struct socket **sockp,
	__u32 local_ip, int local_port);

int ksock_set_sendbufsize(struct socket *sock, int size);

int ksock_set_rcvbufsize(struct socket *sock, int size);

int ksock_connect(struct socket **sockp, __u32 local_ip, int local_port,
			__u32 peer_ip, int peer_port);

void ksock_release(struct socket *sock);

int ksock_write_timeout(struct socket *sock, void *buffer, u32 nob,
	u64 ticks, u32 *pwrote);

int ksock_read_timeout(struct socket *sock, void *buffer, u32 nob,
	u64 ticks, u32 *pread);

int ksock_read(struct socket *sock, void *buffer, u32 nob, u32 *pread);
int ksock_write(struct socket *sock, void *buffer, u32 nob, u32 *pwrote);

int ksock_listen(struct socket **sockp, __u32 local_ip, int local_port,
	int backlog);

int ksock_accept(struct socket **newsockp, struct socket *sock);

void ksock_abort_accept(struct socket *sock);

int ksock_ioctl(struct socket *sock, int cmd, unsigned long arg);

int ksock_set_nodelay(struct socket *sock, bool no_delay);

#endif
