/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source: /cvsroot/curl/curl/lib/sendf.c,v $
 * $Revision: 1.6 $
 * $Date: 2000-08-24 14:26:33 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#endif

#include <curl/curl.h>
#include "urldata.h"

#include <curl/mprintf.h>

/* infof() is for info message along the way */

void infof(struct UrlData *data, char *fmt, ...)
{
  va_list ap;
  if(data->bits.verbose) {
    va_start(ap, fmt);
    fputs("* ", data->err);
    vfprintf(data->err, fmt, ap);
    va_end(ap);
  }
}

/* failf() is for messages stating why we failed, the LAST one will be
   returned for the user (if requested) */

void failf(struct UrlData *data, char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if(data->errorbuffer)
    vsprintf(data->errorbuffer, fmt, ap);
  else /* no errorbuffer receives this, write to data->err instead */
    vfprintf(data->err, fmt, ap);
  va_end(ap);
}

/* sendf() sends the formated data to the server */
int sendf(int fd, struct UrlData *data, char *fmt, ...)
{
  size_t bytes_written;
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = mvaprintf(fmt, ap);
  va_end(ap);
  if(!s)
    return 0; /* failure */
  if(data->bits.verbose)
    fprintf(data->err, "> %s", s);
#ifndef USE_SSLEAY
   bytes_written = swrite(fd, s, strlen(s));
#else
  if (data->use_ssl) {
    bytes_written = SSL_write(data->ssl, s, strlen(s));
  } else {
    bytes_written = swrite(fd, s, strlen(s));
  }
#endif /* USE_SSLEAY */
  free(s); /* free the output string */
  return(bytes_written);
}

/* ssend() sends plain (binary) data to the server */
size_t ssend(int fd, struct UrlData *data, void *mem, size_t len)
{
  size_t bytes_written;

  if(data->bits.verbose)
    fprintf(data->err, "> [binary output]\n");
#ifndef USE_SSLEAY
   bytes_written = swrite(fd, mem, len);
#else
  if (data->use_ssl) {
    bytes_written = SSL_write(data->ssl, mem, len);
  } else {
    bytes_written = swrite(fd, mem, len);
  }
#endif /* USE_SSLEAY */
  return bytes_written;
}




