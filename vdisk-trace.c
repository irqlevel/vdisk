#define CREATE_TRACE_POINTS
#include "vdisk-trace.h"

void vdisk_trace_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	trace_printf(fmt, args);
	va_end(args);
}

void vdisk_trace_error(int err, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	trace_error(err, fmt, args);
	va_end(args);
}
