#ifndef __HOSTIP_H
#define __HOSTIP_H
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
 * $Id: hostip.h,v 1.12 2001-10-04 13:25:12 bagder Exp $
 *****************************************************************************/

struct addrinfo;
struct hostent;
struct SessionHandle;

/* Get name info */
Curl_addrinfo *Curl_getaddrinfo(struct SessionHandle *data,
                                char *hostname,
                                int port,
                                char **bufp);
/* free name info */
void Curl_freeaddrinfo(void *freethis);

#ifdef MALLOCDEBUG
void curl_freeaddrinfo(struct addrinfo *freethis,
                       int line, const char *source);
int curl_getaddrinfo(char *hostname, char *service,
                     struct addrinfo *hints,
                     struct addrinfo **result,
                     int line, const char *source);
#endif

#endif
