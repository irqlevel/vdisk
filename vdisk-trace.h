#if !defined(_TRACE_VDISK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VDISK_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM vdisk

#define VDISK_MSG_CHARS	256

TRACE_EVENT(printf,
	TP_PROTO(const char *fmt, va_list args),
	TP_ARGS(fmt, args),

	TP_STRUCT__entry(
		__dynamic_array(char, message, VDISK_MSG_CHARS)
	),

	TP_fast_assign(
		vsnprintf((char *)__get_str(message),
			  VDISK_MSG_CHARS - 1, fmt, args);
		((char *)__get_str(message))[VDISK_MSG_CHARS - 1] = '\0';
	),

	TP_printk("%s", __get_str(message))
);

TRACE_EVENT(error,
	TP_PROTO(int err, const char *fmt, va_list args),
	TP_ARGS(err, fmt, args),

	TP_STRUCT__entry(
		__dynamic_array(char, message, VDISK_MSG_CHARS)
		__field(int, err)
	),

	TP_fast_assign(
		vsnprintf((char *)__get_str(message),
			  VDISK_MSG_CHARS - 1, fmt, args);
		((char *)__get_str(message))[VDISK_MSG_CHARS - 1] = '\0';
		__entry->err = err;
	),

	TP_printk("%d: %s", __entry->err, __get_str(message))
);

TRACE_EVENT(disk_create,
	TP_PROTO(void *disk, const char *name),
	TP_ARGS(disk, name),

	TP_STRUCT__entry(
		__dynamic_array(char, name, VDISK_MSG_CHARS)
		__field(void *, disk)
	),

	TP_fast_assign(
		snprintf((char *)__get_str(name),
			  VDISK_MSG_CHARS - 1, "%s", name);
		((char *)__get_str(name))[VDISK_MSG_CHARS - 1] = '\0';
		__entry->disk = disk;
	),

	TP_printk("disk 0x%p name %s",
		  __entry->disk, __get_str(name))
);

TRACE_EVENT(disk_destroy,
	TP_PROTO(void *disk),
	TP_ARGS(disk),

	TP_STRUCT__entry(
		__field(void *, disk)
	),

	TP_fast_assign(
		__entry->disk = disk;
	),

	TP_printk("disk 0x%p", __entry->disk)
);

#endif /* _TRACE_VDISK_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE vdisk-trace

/* This part must be outside protection */
#include <trace/define_trace.h>
