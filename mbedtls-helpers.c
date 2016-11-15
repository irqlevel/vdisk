#include "mbedtls-helpers.h"
#include "vdisk.h"

#include <linux/random.h>
#include "mbedtls/mbedtls/platform.h"

int __mbedtls_rand(void)
{
	int v;

	get_random_bytes(&v, sizeof(v));
	return v;
}

void *__mbedtls_calloc(size_t n, size_t size)
{
	return vdisk_kcalloc(n, size, GFP_KERNEL);
}

void __mbedtls_free(void *ptr)
{
	return vdisk_kfree(ptr);
}

int __mbedtls_snprintf(char *s, size_t n, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vsnprintf(s, n, fmt, args);
	va_end(args);
	return r;
}

int mbedtls_platform_entropy_poll(void *data, unsigned char *output,
				  size_t len, size_t *olen)
{
	get_random_bytes(output, len);
	*olen = len;
	return 0;
}

void mbedtls_setup_callbacks(void)
{
	mbedtls_platform_set_calloc_free(__mbedtls_calloc, __mbedtls_free);
	mbedtls_platform_set_snprintf(__mbedtls_snprintf);
}
