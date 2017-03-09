#ifndef __PORTABLE_H__
#define __PORTABLE_H__

extern int debugmode;

#ifndef WIN32
#define dbg_printf(fmt, args...)	do{ if(debugmode) fprintf(stderr, fmt, ## args); } while(0)
#else

#ifdef DEBUG
#define dbg_printf(fmt, ...)	fprintf(stderr, fmt, __VA_ARGS__)
#else
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

#endif /* __PORTABLE_H__ */
