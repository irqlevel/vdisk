#ifndef __MBEDTLS_HELPERS_H__
#define __MBEDTLS_HELPERS_H__

#include <linux/kernel.h>

int mbedtls_platform_entropy_poll(void *data, unsigned char *output,
				  size_t len, size_t *olen);

void mbedtls_setup_callbacks(void);

#endif
