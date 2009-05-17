#ifndef HEADER_CARES_LIBRARY_INIT_H
#define HEADER_CARES_LIBRARY_INIT_H

/* $Id: ares_library_init.h,v 1.1 2009-05-17 17:10:41 yangtse Exp $ */

#include "setup.h"

#ifdef WIN32

#include <iphlpapi.h>

typedef DWORD (WINAPI *fpGetNetworkParams_t) (FIXED_INFO*, DWORD*);
typedef BOOLEAN (APIENTRY *fpSystemFunction036_t) (void*, ULONG);

/* Forward-declaration of variables defined in ares_library_init.c */
/* that are global and unique instances for whole c-ares library.  */

extern fpGetNetworkParams_t fpGetNetworkParams;
extern fpSystemFunction036_t fpSystemFunction036;

#endif /* WIN32 */

#endif /* HEADER_CARES_LIBRARY_INIT_H */

