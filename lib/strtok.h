/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id: strtok.h,v 1.4 2001-05-31 06:05:32 bagder Exp $
 *****************************************************************************/

#ifndef _CURL_STRTOK_R_H
#define _CURL_STRTOK_R_H

#include <stddef.h>
#include "setup.h"

#ifndef HAVE_STRTOK_R
char *Curl_strtok_r(char *s, const char *delim, char **last);
#define strtok_r Curl_strtok_r
#else
#include <string.h>
/* If your system, such as Solaris 2.7, lacks the strtok_r() prototype in
   string.h, then you'll face a bunch of warnings on all instances
   where strtok_r() is used.

   There's not much we can do about it. Adding a prototype here screws
   everything up on other platforms! :-(
*/
#endif

#endif

