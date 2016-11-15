#include "mbedtls-helpers.h"
#include "vdisk.h"

#include <linux/random.h>

int mbedtls_rand(void)
{
	int v;

	get_random_bytes(&v, sizeof(v));
	return v;
}

void *mbedtls_calloc(size_t n, size_t size)
{
	return vdisk_kcalloc(n, size, GFP_KERNEL);
}

void mbedtls_free(void *ptr)
{
	return vdisk_kfree(ptr);
}

int mbedtls_snprintf(char *s, size_t n, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vsnprintf(s, n, fmt, args);
	va_end(args);
	return r;
}

int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
	get_random_bytes(output, len);
	*olen = len;
	return 0;
}
