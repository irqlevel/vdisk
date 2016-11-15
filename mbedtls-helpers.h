#ifndef __MBEDTLS_HELPERS_H__
#define __MBEDTLS_HELPERS_H__

#include <linux/kernel.h>

int mbedtls_rand(void);

void *mbedtls_calloc(size_t n, size_t size);

void mbedtls_free(void *ptr);

int mbedtls_snprintf(char *s, size_t n, const char *fmt, ...);

int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );

#endif
