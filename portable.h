#ifndef __PORTABLE_H__
#define __PORTABLE_H__

extern int debugmode;

#ifndef WIN32
#define dbg_printf(fmt, args...)	do{ if(debugmode) fprintf(stderr, fmt, ## args); } while(0)
#define dbg_dump_long(src, cnt, addr, skip) do{ if(debugmode) dump_long(src, cnt, addr, skip); } while(0)
#else

#ifdef DEBUG
#define dbg_printf(fmt, ...)	fprintf(stderr, fmt, __VA_ARGS__)
#define dbg_dump_long(src, cnt, addr, skip) dump_long(src, cnt, addr, skip)
#else
#define dbg_dump_long(src, cnt, addr, skip)
#define dbg_printf(fmt, ...)    /* Don't do anything in release builds */
#endif
#endif

#ifndef _MSC_VER
#include <unistd.h>
#endif
#ifdef WIN32
#include <Windows.h>
#include <direct.h>
#include <io.h>
#endif
#ifdef __linux__
#include <linux/limits.h>
#endif
#ifdef __APPLE__
#include <sys/syslimits.h>
#endif
#ifdef __FreeBSD__
#include <sys/param.h>
#endif

#ifndef WIN32
#define PATH_SEPARATOR '/'
#define msleep(ms) usleep((ms) * 1000)
#else
#define PATH_MAX MAX_PATH
#define PATH_SEPARATOR '\\'
#define msleep(ms) Sleep(ms)
#endif

#ifdef _MSC_VER
#define R_OK 04

#define open(filename,oflag)	_open(filename,oflag)
#define write(fd,buffer,count)	_write(fd,buffer,count)
#define read(fd,buffer,count)	_read(fd,buffer,count)
#define close(fd)				_close(fd)
#define access(filename,oflag)	_access(filename,oflag)
#define getcwd(buffer, maxlen)	_getcwd(buffer, maxlen)
#endif

#ifdef __GNUC__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BE32(x) __builtin_bswap32(x)
#define BE16(x) __builtin_bswap16(x)
#else
#define BE32(x) x
#define BE16(x) x
#endif
#elif _MSC_VER // assume little endian...
#define BE32(x) _byteswap_ulong(x)
#define BE16(x) _byteswap_ushort(x)
#endif

#endif /* __PORTABLE_H__ */
