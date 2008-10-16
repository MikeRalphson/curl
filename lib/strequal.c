/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: strequal.c,v 1.37 2008-10-16 07:59:00 bagder Exp $
 ***************************************************************************/

#include "setup.h"

#include <string.h>
#include <ctype.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "strequal.h"

int curl_strequal(const char *first, const char *second)
{
#if defined(HAVE_STRCASECMP)
  return !(strcasecmp)(first, second);
#elif defined(HAVE_STRCMPI)
  return !(strcmpi)(first, second);
#elif defined(HAVE_STRICMP)
  return !(stricmp)(first, second);
#else
  while(*first && *second) {
    if(toupper(*first) != toupper(*second)) {
      break;
    }
    first++;
    second++;
  }
  return toupper(*first) == toupper(*second);
#endif
}

int curl_strnequal(const char *first, const char *second, size_t max)
{
#if defined(HAVE_STRNCASECMP)
  return !strncasecmp(first, second, max);
#elif defined(HAVE_STRNCMPI)
  return !strncmpi(first, second, max);
#elif defined(HAVE_STRNICMP)
  return !strnicmp(first, second, max);
#else
  while(*first && *second && max) {
    if(toupper(*first) != toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return toupper(*first) == toupper(*second);
#endif
}

/* Portable toupper (remember EBCDIC). Do not use tupper() because
   its behavior is altered by the current locale. */
static bool my_toupper(unsigned char in)
{
  switch (in) {
  case 'a':
    return 'A';
  case 'b':
    return 'B';
  case 'c':
    return 'C';
  case 'd':
    return 'D';
  case 'e':
    return 'E';
  case 'f':
    return 'F';
  case 'g':
    return 'G';
  case 'h':
    return 'H';
  case 'i':
    return 'I';
  case 'j':
    return 'J';
  case 'k':
    return 'K';
  case 'l':
    return 'L';
  case 'm':
    return 'M';
  case 'n':
    return 'N';
  case 'o':
    return 'O';
  case 'p':
    return 'P';
  case 'q':
    return 'Q';
  case 'r':
    return 'R';
  case 's':
    return 'S';
  case 't':
    return 'T';
  case 'u':
    return 'U';
  case 'v':
    return 'V';
  case 'w':
    return 'W';
  case 'x':
    return 'X';
  case 'y':
    return 'Y';
  case 'z':
    return 'Z';
  }
  return in;
}

/*
 * Curl_ascii_equal() is for doing "ascii" case insensitive strings. This is
 * meant to be locale independent and only compare strings we know are safe
 * for this.
 * See http://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for some
 * further explanation to why this function is necessary.
 */

int Curl_ascii_equal(const char *first, const char *second)
{
  while(*first && *second) {
    if(! (my_toupper(*first) == my_toupper(*second)))
      /* get out of the loop as soon as they don't match */
      break;
    first++;
    second++;
  }
  /* we do the comparison here (possibly again), just to make sure that if the
     loop above is skipped because one of the strings reached zero, we must not
     return this as a successful match */
  return (my_toupper(*first) == my_toupper(*second));
}

#ifndef HAVE_STRLCAT
/*
 * The strlcat() function appends the NUL-terminated string src to the end
 * of dst. It will append at most size - strlen(dst) - 1 bytes, NUL-termi-
 * nating the result.
 *
 * The strlcpy() and strlcat() functions return the total length of the
 * string they tried to create.  For strlcpy() that means the length of src.
 * For strlcat() that means the initial length of dst plus the length of
 * src. While this may seem somewhat confusing it was done to make trunca-
 * tion detection simple.
 *
 *
 */
size_t Curl_strlcat(char *dst, const char *src, size_t siz)
{
  char *d = dst;
  const char *s = src;
  size_t n = siz;
  size_t dlen;

  /* Find the end of dst and adjust bytes left but don't go past end */
  while(n-- != 0 && *d != '\0')
    d++;
  dlen = d - dst;
  n = siz - dlen;

  if(n == 0)
    return(dlen + strlen(s));
  while(*s != '\0') {
    if(n != 1) {
      *d++ = *s;
      n--;
    }
    s++;
  }
  *d = '\0';

  return(dlen + (s - src));     /* count does not include NUL */
}
#endif
