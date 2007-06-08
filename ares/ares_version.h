/* $Id: ares_version.h,v 1.9 2007-06-08 09:01:33 bagder Exp $ */

#ifndef ARES__VERSION_H
#define ARES__VERSION_H

#define ARES_VERSION_MAJOR 1
#define ARES_VERSION_MINOR 4
#define ARES_VERSION_PATCH 1
#define ARES_VERSION ((ARES_VERSION_MAJOR<<16)|\
                       (ARES_VERSION_MINOR<<8)|\
                       (ARES_VERSION_PATCH))
#define ARES_VERSION_STR "1.4.1-CVS"

#ifdef  __cplusplus
extern "C" {
#endif

const char *ares_version(int *version);

#ifdef  __cplusplus
}
#endif

#endif

