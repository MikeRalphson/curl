/* $Id: ares_version.h,v 1.15 2008-12-09 22:41:36 bagder Exp $ */

#ifndef ARES__VERSION_H
#define ARES__VERSION_H

#define ARES_VERSION_MAJOR 1
#define ARES_VERSION_MINOR 6
#define ARES_VERSION_PATCH 1
#define ARES_VERSION ((ARES_VERSION_MAJOR<<16)|\
                       (ARES_VERSION_MINOR<<8)|\
                       (ARES_VERSION_PATCH))
#define ARES_VERSION_STR "1.6.1-CVS"

#ifdef  __cplusplus
extern "C" {
#endif

const char *ares_version(int *version);

#ifdef  __cplusplus
}
#endif

#endif

