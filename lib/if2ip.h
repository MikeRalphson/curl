#ifndef __IF2IP_H
#define __IF2IP_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 * 
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id: if2ip.h,v 1.9 2002-09-03 11:53:00 bagder Exp $
 ***************************************************************************/
#include "setup.h"

#if ! defined(WIN32) && ! defined(__BEOS__) && !defined(__CYGWIN32__)
extern char *Curl_if2ip(char *interface, char *buf, int buf_size);
#else
#define Curl_if2ip(a,b,c) NULL
#endif

#endif
