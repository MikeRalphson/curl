#ifndef HEADER_CARES_LIBRARY_INIT_H
#define HEADER_CARES_LIBRARY_INIT_H

/* $Id: ares_library_init.h,v 1.2 2009-05-19 15:23:25 yangtse Exp $ */

/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2004-2009 by Daniel Stenberg
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

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

