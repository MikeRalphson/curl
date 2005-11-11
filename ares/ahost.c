/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "setup.h"
#include <sys/types.h>

#ifdef WIN32
#else
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"
#include "ares_dns.h"
#include "inet_ntop.h"
#include "inet_net_pton.h"

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr
{
  unsigned char s6_addr[16];
};
#endif

static void callback(void *arg, int status, struct hostent *host);
static void usage(void);

int main(int argc, char **argv)
{
  ares_channel channel;
  int status, nfds;
  fd_set read_fds, write_fds;
  struct timeval *tvp, tv;
  struct in_addr addr4;
  struct in6_addr addr6;

#ifdef WIN32
  WORD wVersionRequested = MAKEWORD(1,1);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

  if (argc <= 1)
    usage();

  status = ares_init(&channel);
  if (status != ARES_SUCCESS)
    {
      fprintf(stderr, "ares_init: %s\n", ares_strerror(status));
      return 1;
    }

  /* Initiate the queries, one per command-line argument. */
  for (argv++; *argv; argv++)
    {
      if (ares_inet_pton(AF_INET, *argv, &addr4) == 1)
        {
          ares_gethostbyaddr(channel, &addr4, sizeof(addr4), AF_INET, callback,
                             *argv);
        }
      else if (ares_inet_pton(AF_INET6, *argv, &addr6) == 1)
        {
          ares_gethostbyaddr(channel, &addr6, sizeof(addr6), AF_INET6, callback,
                             *argv);
        }
      else
        {
          /* assume user wants A-records */
          ares_gethostbyname(channel, *argv, AF_INET, callback, *argv);
        }
    }

  /* Wait for all queries to complete. */
  while (1)
    {
      FD_ZERO(&read_fds);
      FD_ZERO(&write_fds);
      nfds = ares_fds(channel, &read_fds, &write_fds);
      if (nfds == 0)
        break;
      tvp = ares_timeout(channel, NULL, &tv);
      select(nfds, &read_fds, &write_fds, NULL, tvp);
      ares_process(channel, &read_fds, &write_fds);
    }

  ares_destroy(channel);
  return 0;
}

static void callback(void *arg, int status, struct hostent *host)
{
  char **p;

  if (status != ARES_SUCCESS)
    {
      fprintf(stderr, "%s: %s\n", (char *) arg, ares_strerror(status));
      return;
    }

  for (p = host->h_addr_list; *p; p++)
    {
      char addr_buf[46] = "??";

      ares_inet_ntop(host->h_addrtype, *p, addr_buf, sizeof(addr_buf));
      printf("%-32s\t%s", host->h_name, addr_buf);
#if 0
      if (host->h_aliases[0])
        {
           int i;

	   printf (", Aliases: ");
	   for (i = 0; host->h_aliases[i]; i++)
               printf("%s ", host->h_aliases[i]);
        }
#endif
      puts("");
    }
}

static void usage(void)
{
  fprintf(stderr, "usage: ahost {host|addr} ...\n");
  exit(1);
}
