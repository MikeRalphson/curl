#ifndef __URL_H
#define __URL_H
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
 * $Id: url.h,v 1.6 2001-08-15 06:53:34 bagder Exp $
 *****************************************************************************/

/*
 * Prototypes for library-wide functions provided by url.c
 */

CURLcode Curl_open(struct UrlData **curl);
CURLcode Curl_setopt(struct UrlData *data, CURLoption option, ...);
CURLcode Curl_close(struct UrlData *data); /* the opposite of curl_open() */
CURLcode Curl_connect(struct UrlData *,
                      struct connectdata **,
                      bool allow_port);
CURLcode Curl_do(struct connectdata *);
CURLcode Curl_done(struct connectdata *);
CURLcode Curl_disconnect(struct connectdata *);

#endif
