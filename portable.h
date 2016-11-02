#ifndef __PORTABLE_H__
#define __PORTABLE_H__

#ifndef WIN32
#include <unistd.h>
#else
#include <Windows.h>
#endif


#ifndef WIN32
#define PATH_SEPARATOR '/'
#define msleep(ms) usleep((ms) * 1000)
#else
#define PATH_SEPARATOR '\\'
#define msleep(ms) Sleep(ms)
#endif

#endif /* __PORTABLE_H__ */
