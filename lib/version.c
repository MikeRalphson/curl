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
 * $Id: version.c,v 1.19 2002-09-25 07:08:42 bagder Exp $
 ***************************************************************************/

#include "setup.h"

#include <string.h>
#include <stdio.h>

#include <curl/curl.h>
#include "urldata.h"

char *curl_version(void)
{
  static char version[200];
  char *ptr;
  strcpy(version, LIBCURL_NAME "/" LIBCURL_VERSION );
  ptr=strchr(version, '\0');

#ifdef USE_SSLEAY

#if (SSLEAY_VERSION_NUMBER >= 0x905000)
  {
    char sub[2];
    unsigned long ssleay_value;
    sub[1]='\0';
    ssleay_value=SSLeay();
    if(ssleay_value < 0x906000) {
      ssleay_value=SSLEAY_VERSION_NUMBER;
      sub[0]='\0';
    }
    else {
      if(ssleay_value&0xff0) {
        sub[0]=((ssleay_value>>4)&0xff) + 'a' -1;
      }
      else
        sub[0]='\0';
    }

    sprintf(ptr, " OpenSSL/%lx.%lx.%lx%s",
            (ssleay_value>>28)&0xf,
            (ssleay_value>>20)&0xff,
            (ssleay_value>>12)&0xff,
            sub);
  }

#else
#if (SSLEAY_VERSION_NUMBER >= 0x900000)
  sprintf(ptr, " OpenSSL/%lx.%lx.%lx",
          (SSLEAY_VERSION_NUMBER>>28)&0xff,
          (SSLEAY_VERSION_NUMBER>>20)&0xff,
          (SSLEAY_VERSION_NUMBER>>12)&0xf);
#else
  {
    char sub[2];
    sub[1]='\0';
    if(SSLEAY_VERSION_NUMBER&0x0f) {
      sub[0]=(SSLEAY_VERSION_NUMBER&0x0f) + 'a' -1;
    }
    else
      sub[0]='\0';

    sprintf(ptr, " SSL/%x.%x.%x%s",
            (SSLEAY_VERSION_NUMBER>>12)&0xff,
            (SSLEAY_VERSION_NUMBER>>8)&0xf,
            (SSLEAY_VERSION_NUMBER>>4)&0xf, sub);
  }
#endif
#endif
  ptr=strchr(ptr, '\0');
#endif

#ifdef KRB4
  sprintf(ptr, " krb4");
  ptr += strlen(ptr);
#endif
#ifdef ENABLE_IPV6
  sprintf(ptr, " ipv6");
  ptr += strlen(ptr);
#endif
#ifdef HAVE_LIBZ
  sprintf(ptr, " zlib/%s", zlibVersion());
  ptr += strlen(ptr);
#endif

  return version;
}

/* data for curl_version_info */

static const curl_runtime_protocol_info protocols[] = {
#ifndef CURL_DISABLE_FTP
  { "ftp" },
#endif
#ifndef CURL_DISABLE_GOPHER
  { "gopher" },
#endif
#ifndef CURL_DISABLE_TELNET
  { "telnet" },
#endif
#ifndef CURL_DISABLE_DICT
  { "dict" },
#endif
#ifndef CURL_DISABLE_LDAP
  { "ldap" },
#endif
#ifndef CURL_DISABLE_HTTP
  { "http" },
#endif
#ifndef CURL_DISABLE_FILE
  { "file" },
#endif

#ifdef USE_SSLEAY
#ifndef CURL_DISABLE_HTTP
  { "https" },
#endif
#ifndef CURL_DISABLE_FTP
  { "ftps" },
#endif
#endif
  { NULL }
};

static const curl_version_info_data version_info = {
  LIBCURL_VERSION,
  LIBCURL_VERSION_NUM,
  &protocols
};

const curl_version_info_data *curl_version_info(void)
{
  return &version_info;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
