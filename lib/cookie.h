#ifndef __COOKIE_H
#define __COOKIE_H
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
 * $Id: cookie.h,v 1.3 2001-01-03 09:29:34 bagder Exp $
 *****************************************************************************/

#include <stdio.h>
#ifdef WIN32
#include <time.h>
#else
#include <sys/time.h>
#endif

#include <curl/curl.h>

struct Cookie {
  struct Cookie *next; /* next in the chain */
  char *name;        /* <this> = value */
  char *value;       /* name = <this> */
  char *path;	      /* path = <this> */
  char *domain;      /* domain = <this> */
  time_t expires;    /* expires = <this> */
  char *expirestr;   /* the plain text version */
  
  /* RFC 2109 keywords. Version=1 means 2109-compliant cookie sending */
  char *version;     /* Version = <value> */
  char *maxage;      /* Max-Age = <value> */
  
  bool secure;       /* whether the 'secure' keyword was used */
};

struct CookieInfo {
   /* linked list of cookies we know of */
   struct Cookie *cookies;

   char *filename; /* file we read from/write to */
};

/* This is the maximum line length we accept for a cookie line */
#define MAX_COOKIE_LINE 2048
#define MAX_COOKIE_LINE_TXT "2047"

/* This is the maximum length of a cookie name we deal with: */
#define MAX_NAME 256
#define MAX_NAME_TXT "255"

struct Cookie *cookie_add(struct CookieInfo *, bool, char *);
struct CookieInfo *cookie_init(char *);
struct Cookie *cookie_getlist(struct CookieInfo *, char *, char *, bool);
void cookie_freelist(struct Cookie *);
void cookie_cleanup(struct CookieInfo *);

#endif
