#ifndef __MULTI_H
#define __MULTI_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: multi.h,v 1.13 2005-01-11 14:32:09 giva Exp $
 ***************************************************************************/

 /* This file shadows for <curl/multi.h> in some compilers
 */
#include <curl/multi.h>

/*
 * Prototypes for library-wide functions provided by multi.c
 */
void Curl_multi_rmeasy(void *multi, CURL *data);

#endif /* __MULTI_H */
