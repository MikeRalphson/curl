#ifndef __TIMEVAL_H
#define __TIMEVAL_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source: /cvsroot/curl/curl/lib/timeval.h,v $
 * $Revision: 1.2 $
 * $Date: 2000-01-10 23:36:15 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <time.h>
#else
#include <sys/time.h>
#endif

#include "setup.h"

#ifndef HAVE_GETTIMEOFDAY
#if !defined(_WINSOCKAPI_) && !defined(__MINGW32__)
struct timeval {
 long tv_sec;
 long tv_usec;
};
#endif
#endif

struct timeval tvnow ();
double tvdiff (struct timeval t1, struct timeval t2);
long tvlong (struct timeval t1);

#endif
