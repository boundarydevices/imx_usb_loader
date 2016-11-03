#ifndef __PORTABLE_H__
#define __PORTABLE_H__

#ifndef WIN32
#include <unistd.h>
#else
#include <Windows.h>
#include <io.h>
#endif


#ifndef WIN32
#define PATH_SEPARATOR '/'
#define msleep(ms) usleep((ms) * 1000)
#else
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
#endif

#endif /* __PORTABLE_H__ */
