/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: share.c,v 1.6 2003-01-29 10:14:23 bagder Exp $
 ***************************************************************************/

#include "setup.h"
#include <stdlib.h>
#include <curl/curl.h>
#include "urldata.h"
#include "share.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

CURLSH *
curl_share_init(void)
{
  struct Curl_share *share =
    (struct Curl_share *)malloc(sizeof(struct Curl_share));
  if (share)
    memset (share, 0, sizeof(struct Curl_share));

  return share;
}

CURLSHcode
curl_share_setopt(CURLSH *sh, CURLSHoption option, ...)
{
  struct Curl_share *share = (struct Curl_share *)sh;
  va_list param;
  int type;
  curl_lock_function lockfunc;
  curl_unlock_function unlockfunc;
  void *ptr;

  if (share->dirty)
    /* don't allow setting options while one or more handles are already
       using this share */
    return CURLSHE_IN_USE;

  va_start(param, option);

  switch(option) {
  case CURLSHOPT_SHARE:
    /* this is a type this share will share */
    type = va_arg(param, int);
    share->specifier |= (1<<type);
    break;

  case CURLSHOPT_UNSHARE:
    /* this is a type this share will no longer share */
    type = va_arg(param, int);
    share->specifier &= ~(1<<type);
    break;

  case CURLSHOPT_LOCKFUNC:
    lockfunc = va_arg(param, curl_lock_function);
    share->lockfunc = lockfunc;
    break;

  case CURLSHOPT_UNLOCKFUNC:
    unlockfunc = va_arg(param, curl_unlock_function);
    share->unlockfunc = unlockfunc;    
    break;

  case CURLSHOPT_USERDATA:
    ptr = va_arg(param, void *);
    share->clientdata = ptr;
    break;

  default:
    return CURLSHE_BAD_OPTION;
  }

  return CURLSHE_OK;
}

CURLSHcode curl_share_cleanup(CURLSH *sh)
{
  struct Curl_share *share = (struct Curl_share *)sh;
  if (share->dirty)
    return CURLSHE_IN_USE;

  free (share);
  
  return CURLSHE_OK;
}


CURLSHcode
Curl_share_acquire_lock(struct SessionHandle *data, curl_lock_data type)
{
  struct Curl_share *share = data->share;

  if (share == NULL)
    return CURLSHE_INVALID;

  if(share->specifier & (1<<type)) {
    share->lockfunc (data, type, CURL_LOCK_ACCESS_SINGLE, share->clientdata);
    share->locked |= (1<<type);
  }
  /* else if we don't share this, pretend successful lock */

  return CURLSHE_OK;
}

CURLSHcode
Curl_share_release_lock(struct SessionHandle *data, curl_lock_data type)
{
  struct Curl_share *share = data->share;

  if (share == NULL)
    return CURLSHE_INVALID;

  if(share->specifier & (1<<type)) {
    share->unlockfunc (data, type, share->clientdata);
    share->locked &= ~(1<<type);
  }

  return CURLSHE_OK;
}
