#ifndef __CURL_SHARE_H
#define __CURL_SHARE_H

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
 * $Id: share.h,v 1.2 2002-09-03 11:53:01 bagder Exp $
 ***************************************************************************/

#include "setup.h"
#include <curl/curl.h>

typedef enum {
  SHARE_ERROR_OK = 0,
  SHARE_ERROR_INVALID, 
  SHARE_ERROR_NOT_REGISTERED,
  SHARE_ERROR_LAST
} Curl_share_error;

Curl_share_error Curl_share_aquire_lock (CURL *, curl_lock_type);
Curl_share_error Curl_share_release_lock (CURL *, curl_lock_type);

#endif /* __CURL_SHARE_H */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
