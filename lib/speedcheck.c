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
 * $Id: speedcheck.c,v 1.7 2001-01-03 09:29:34 bagder Exp $
 *****************************************************************************/

#include "setup.h"

#include <stdio.h>
#if defined(__MINGW32__)
#include <winsock.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "speedcheck.h"

void speedinit(struct UrlData *data)
{
  memset(&data->keeps_speed, 0, sizeof(struct timeval));
}

CURLcode speedcheck(struct UrlData *data,
                    struct timeval now)
{
  if((data->progress.current_speed >= 0) &&
     data->low_speed_time &&
     (tvlong(data->keeps_speed) != 0) &&
     (data->progress.current_speed < data->low_speed_limit)) {

    /* We are now below the "low speed limit". If we are below it
       for "low speed time" seconds we consider that enough reason
       to abort the download. */
    
    if( tvdiff(now, data->keeps_speed) > data->low_speed_time) {
      /* we have been this slow for long enough, now die */
      failf(data,
	    "Operation too slow. "
	    "Less than %d bytes/sec transfered the last %d seconds",
	    data->low_speed_limit,
	    data->low_speed_time);
      return CURLE_OPERATION_TIMEOUTED;
    }
  }
  else {
    /* we keep up the required speed all right */
    data->keeps_speed = now;
  }
  return CURLE_OK;
}

