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
 * $Id: version.c,v 1.7 2001-01-03 09:29:34 bagder Exp $
 *****************************************************************************/

#include "setup.h"

#include <string.h>
#include <stdio.h>

#include <curl/curl.h>
#include "urldata.h"

char *curl_version(void)
{
  static char version[200];
  char *ptr;
#if defined(USE_SSLEAY)
  static char sub[2];
#endif
  strcpy(version, LIBCURL_NAME " " LIBCURL_VERSION );
  ptr=strchr(version, '\0');

#ifdef USE_SSLEAY

#if (SSLEAY_VERSION_NUMBER >= 0x900000)
  sprintf(ptr, " (SSL %lx.%lx.%lx)",
          (SSLEAY_VERSION_NUMBER>>28)&0xff,
          (SSLEAY_VERSION_NUMBER>>20)&0xff,
          (SSLEAY_VERSION_NUMBER>>12)&0xf);
#else
  if(SSLEAY_VERSION_NUMBER&0x0f) {
    sub[0]=(SSLEAY_VERSION_NUMBER&0x0f) + 'a' -1;
  }
  else
    sub[0]=0;

  sprintf(ptr, " (SSL %x.%x.%x%s)",
          (SSLEAY_VERSION_NUMBER>>12)&0xff,
          (SSLEAY_VERSION_NUMBER>>8)&0xf,
          (SSLEAY_VERSION_NUMBER>>4)&0xf, sub);

#endif
  ptr=strchr(ptr, '\0');
#endif

#ifdef KRB4
  sprintf(ptr, " (krb4 enabled)");
  ptr += strlen(ptr);
#endif

#ifdef USE_ZLIB
  sprintf(ptr, " (zlib %s)", zlibVersion());
  ptr += strlen(ptr);
#endif

  return version;
}
