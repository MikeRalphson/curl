/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: timeval.c,v 1.13 2002-06-03 12:46:32 bagder Exp $
 *****************************************************************************/

#ifdef WIN32
#include <windows.h>
#endif
#include "timeval.h"

#ifndef HAVE_GETTIMEOFDAY

#ifdef WIN32
int
gettimeofday (struct timeval *tp, void *nothing)
{
#ifdef WITHOUT_MM_LIB
  SYSTEMTIME st;
  time_t tt;
  struct tm tmtm;
  /* mktime converts local to UTC */
  GetLocalTime (&st);
  tmtm.tm_sec = st.wSecond;
  tmtm.tm_min = st.wMinute;
  tmtm.tm_hour = st.wHour;
  tmtm.tm_mday = st.wDay;
  tmtm.tm_mon = st.wMonth - 1;
  tmtm.tm_year = st.wYear - 1900;
  tmtm.tm_isdst = -1;
  tt = mktime (&tmtm);
  tp->tv_sec = tt;
  tp->tv_usec = st.wMilliseconds * 1000;
#else
  /**
   ** The earlier time calculations using GetLocalTime
   ** had a time resolution of 10ms.The timeGetTime, part
   ** of multimedia apis offer a better time resolution
   ** of 1ms.Need to link against winmm.lib for this
   **/
  unsigned long Ticks = 0;
  Ticks = timeGetTime();
  tp->tv_sec = Ticks%1000;
  tp->tv_usec = (Ticks - (tp->tv_sec*1000))*1000;
  
#endif
  return 1;
}
#define HAVE_GETTIMEOFDAY
#endif
#endif

struct timeval Curl_tvnow (void)
{
 struct timeval now;
#ifdef HAVE_GETTIMEOFDAY
 gettimeofday (&now, NULL);
#else
 now.tv_sec = (long) time(NULL);
 now.tv_usec = 0;
#endif
 return now;
}

/*
 * Make sure that the first argument is the more recent time, as otherwise
 * we'll get a weird negative time-diff back...
 */
long Curl_tvdiff (struct timeval newer, struct timeval older)
{
  return (newer.tv_sec-older.tv_sec)*1000+
    (499+newer.tv_usec-older.tv_usec)/1000;
}

long Curl_tvlong (struct timeval t1)
{
 return t1.tv_sec;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
