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
 * $Id: hostip.c,v 1.27 2001-09-12 08:59:00 bagder Exp $
 *****************************************************************************/

#include "setup.h"

#include <string.h>
#include <errno.h>

#define _REENTRANT


#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef	VMS
#include <inet.h>
#include <stdlib.h>
#endif
#endif

#include "urldata.h"
#include "sendf.h"

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* --- resolve name or IP-number --- */

static char *MakeIP(unsigned long num,char *addr, int addr_len)
{
#if defined(HAVE_INET_NTOA) || defined(HAVE_INET_NTOA_R)
  struct in_addr in;
  in.s_addr = htonl(num);

#if defined(HAVE_INET_NTOA_R)
  inet_ntoa_r(in,addr,addr_len);
#else
  strncpy(addr,inet_ntoa(in),addr_len);
#endif
#else
  unsigned char *paddr;

  num = htonl(num);  /* htonl() added to avoid endian probs */
  paddr = (unsigned char *)&num;
  sprintf(addr, "%u.%u.%u.%u", paddr[0], paddr[1], paddr[2], paddr[3]);
#endif
  return (addr);
}

#ifdef ENABLE_IPV6
struct addrinfo *Curl_getaddrinfo(struct SessionHandle *data,
			       char *hostname,
			       int port)
{
  struct addrinfo hints, *res;
  int error;
  char sbuf[NI_MAXSERV];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  snprintf(sbuf, sizeof(sbuf), "%d", port);
  error = getaddrinfo(hostname, sbuf, &hints, &res);
  if (error) {
    infof(data, "getaddrinfo(3) failed for %s\n", hostname);
    return NULL;
  }
  return res;
}
#endif

/* The original code to this function was once stolen from the Dancer source
   code, written by Bjorn Reese, it has since been patched and modified
   considerably. */

#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif

struct hostent *Curl_gethost(struct SessionHandle *data,
                             char *hostname,
                             char **bufp)
{
  struct hostent *h = NULL;
  unsigned long in;
  int ret; /* this variable is unused on several platforms but used on some */

#define CURL_NAMELOOKUP_SIZE 9000
  /* Allocate enough memory to hold the full name information structs and
   * everything. OSF1 is known to require at least 8872 bytes. The buffer
   * required for storing all possible aliases and IP numbers is according to
   * Stevens' Unix Network Programming 2nd editor, p. 304: 8192 bytes! */
  char *buf = (char *)malloc(CURL_NAMELOOKUP_SIZE);
  if(!buf)
    return NULL; /* major failure */
  *bufp = buf;

  ret = 0; /* to prevent the compiler warning */

  if ( (in=inet_addr(hostname)) != INADDR_NONE ) {
    struct in_addr *addrentry;

    h = (struct hostent*)buf;
    h->h_addr_list = (char**)(buf + sizeof(*h));
    addrentry = (struct in_addr*)(h->h_addr_list + 2);
    addrentry->s_addr = in;
    h->h_addr_list[0] = (char*)addrentry;
    h->h_addr_list[1] = NULL;
    h->h_addrtype = AF_INET;
    h->h_length = sizeof(*addrentry);
    h->h_name = *(h->h_addr_list) + h->h_length;
    /* bad one h->h_name = (char*)(h->h_addr_list + h->h_length); */
    MakeIP(ntohl(in),h->h_name, CURL_NAMELOOKUP_SIZE - (long)(h->h_name) + (long)buf);
  }
#if defined(HAVE_GETHOSTBYNAME_R)
  else {
    int h_errnop;
     /* Workaround for gethostbyname_r bug in qnx nto. It is also _required_
        for some of these functions. */
    memset(buf, 0, CURL_NAMELOOKUP_SIZE);
#ifdef HAVE_GETHOSTBYNAME_R_5
    /* Solaris, IRIX and more */
    if ((h = gethostbyname_r(hostname,
                             (struct hostent *)buf,
                             buf + sizeof(struct hostent),
                             CURL_NAMELOOKUP_SIZE - sizeof(struct hostent),
                             &h_errnop)) == NULL )
#endif
#ifdef HAVE_GETHOSTBYNAME_R_6
    /* Linux */
    if( gethostbyname_r(hostname,
                        (struct hostent *)buf,
                        buf + sizeof(struct hostent),
                        CURL_NAMELOOKUP_SIZE - sizeof(struct hostent),
                        &h, /* DIFFERENCE */
                        &h_errnop))
#endif
#ifdef HAVE_GETHOSTBYNAME_R_3
    /* AIX, Digital Unix, HPUX 10, more? */

    if(CURL_NAMELOOKUP_SIZE >=
       (sizeof(struct hostent)+sizeof(struct hostent_data)))

      /* August 22nd, 2000: Albert Chin-A-Young brought an updated version
       * that should work! September 20: Richard Prescott worked on the buffer
       * size dilemma. */

      ret = gethostbyname_r(hostname,
                          (struct hostent *)buf,
                          (struct hostent_data *)(buf + sizeof(struct hostent)));
    else
      ret = -1; /* failure, too smallish buffer size */
    
    /* result expected in h */
    h = (struct hostent*)buf;
    h_errnop= errno; /* we don't deal with this, but set it anyway */
    if(ret)
#endif
      {
      infof(data, "gethostbyname_r(2) failed for %s\n", hostname);
      h = NULL; /* set return code to NULL */
      free(buf);
      *bufp=NULL;
    }
#else
  else {
    if ((h = gethostbyname(hostname)) == NULL ) {
      infof(data, "gethostbyname(2) failed for %s\n", hostname);
      free(buf);
      *bufp=NULL;
    }
#endif
  }
  return (h);
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: et sw=2 ts=2 sts=2 tw=78 fdm=marker
 * vim<600: et sw=2 ts=2 sts=2 tw=78
 */
