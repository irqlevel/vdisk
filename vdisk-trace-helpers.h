#ifndef __VDISK_TRACE_HELPERS_H__
#define __VDISK_TRACE_HELPERS_H__

void vdisk_trace_printf(const char *fmt, ...);

void vdisk_trace_error(int err, const char *fmt, ...);

#define TRACE(fmt, ...)						\
do {								\
	vdisk_trace_printf("%s: " fmt,				\
				__func__, ##__VA_ARGS__);	\
} while (false)

#define TRACE_ERR(err, fmt, ...)			\
do {							\
	vdisk_trace_error(err, "%s: " fmt,		\
			      __func__, ##__VA_ARGS__);	\
} while (false)

#define TRACE_VERBOSE(fmt, ...)

#endif
