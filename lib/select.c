/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: select.c,v 1.2 2004-11-19 13:46:58 giva Exp $
 ***************************************************************************/

#include "setup.h"

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef HAVE_SELECT
#error "We can't compile without select() support!"
#endif

#include "select.h"

#ifdef WIN32
#define VALID_SOCK(s) (1)  /* Win-sockets are not in range [0..FD_SETSIZE> */
#else
#define VALID_SOCK(s) ((s) >= 0) && ((s) < FD_SETSIZE))
#endif

/*
 * This is an internal function used for waiting for read or write
 * events on single file descriptors.  It attempts to replace select()
 * in order to avoid limits with FD_SETSIZE.
 *
 * Return values:
 *   -1 = system call error
 *    0 = timeout
 *    CSELECT_IN | CSELECT_OUT | CSELECT_ERR
 */
int Curl_select(int readfd, int writefd, int timeout_ms)
{
#ifdef HAVE_POLL_FINE
  struct pollfd pfd[2];
  int num;
  int r;
  int ret;

  num = 0;
  if (readfd != CURL_SOCKET_BAD) {
    pfd[num].fd = readfd;
    pfd[num].events = POLLIN;
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    pfd[num].fd = writefd;
    pfd[num].events = POLLOUT;
    num++;
  }

  r = poll(pfd, num, timeout_ms);

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  ret = 0;
  num = 0;
  if (readfd != CURL_SOCKET_BAD) {
    if (pfd[num].revents & POLLIN)
      ret |= CSELECT_IN;
    if (pfd[num].revents & POLLERR)
      ret |= CSELECT_ERR;
    num++;
  }
  if (writefd != CURL_SOCKET_BAD) {
    if (pfd[num].revents & POLLOUT)
      ret |= CSELECT_OUT;
    if (pfd[num].revents & POLLERR)
      ret |= CSELECT_ERR;
  }

  return ret;
#else
  struct timeval timeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  int maxfd;
  int r;
  int ret;

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  FD_ZERO(&fds_err);
  maxfd = -1;

  FD_ZERO(&fds_read);
  if (readfd != CURL_SOCKET_BAD) {
    if (!VALID_SOCK(readfd)) {
      errno = EINVAL;
      return -1;
    }
    FD_SET(readfd, &fds_read);
    FD_SET(readfd, &fds_err);
    maxfd = readfd;
  }

  FD_ZERO(&fds_write);
  if (writefd != CURL_SOCKET_BAD) {
    if (!VALID_SOCK(writefd)) {
      errno = EINVAL;
      return -1;
    }
    FD_SET(writefd, &fds_write);
    FD_SET(writefd, &fds_err);
    if (writefd > maxfd)
      maxfd = writefd;
  }

  r = select(maxfd + 1, &fds_read, &fds_write, &fds_err, &timeout);

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  ret = 0;
  if (readfd != CURL_SOCKET_BAD) {
    if (FD_ISSET(readfd, &fds_read))
      ret |= CSELECT_IN;
    if (FD_ISSET(readfd, &fds_err))
      ret |= CSELECT_ERR;
  }
  if (writefd != CURL_SOCKET_BAD) {
    if (FD_ISSET(writefd, &fds_write))
      ret |= CSELECT_OUT;
    if (FD_ISSET(writefd, &fds_err))
      ret |= CSELECT_ERR;
  }

  return ret;
#endif
}

/*
 * This is a wrapper around poll().  If poll() does not exist, then
 * select() is used instead.  An error is returned if select() is
 * being used and a file descriptor too large for FD_SETSIZE.
 *
 * Return values:
 *   -1 = system call error or fd >= FD_SETSIZE
 *    0 = timeout
 *    1 = number of structures with non zero revent fields
 */
int Curl_poll(struct pollfd ufds[], unsigned int nfds, int timeout_ms)
{
#ifdef HAVE_POLL_FINE
    return poll(ufds, nfds, timeout_ms);
#else
  struct timeval timeout;
  struct timeval *ptimeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  int maxfd;
  int r;
  unsigned int i;

  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_err);
  maxfd = -1;

  for (i = 0; i < nfds; i++) {
    if (ufds[i].fd < 0)
      continue;
    if (ufds[i].fd >= FD_SETSIZE) {
      errno = EINVAL;
      return -1;
    }
    if (ufds[i].fd > maxfd)
      maxfd = ufds[i].fd;
    if (ufds[i].events & POLLIN)
      FD_SET(ufds[i].fd, &fds_read);
    if (ufds[i].events & POLLOUT)
      FD_SET(ufds[i].fd, &fds_write);
    if (ufds[i].events & POLLERR)
      FD_SET(ufds[i].fd, &fds_err);
  }

  if (timeout_ms < 0) {
    ptimeout = NULL;      /* wait forever */
  } else {
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    ptimeout = &timeout;
  }

  r = select(maxfd + 1, &fds_read, &fds_write, &fds_err, ptimeout);

  if (r < 0)
    return -1;
  if (r == 0)
    return 0;

  r = 0;
  for (i = 0; i < nfds; i++) {
    ufds[i].revents = 0;
    if (ufds[i].fd < 0)
      continue;
    if (FD_ISSET(ufds[i].fd, &fds_read))
      ufds[i].revents |= POLLIN;
    if (FD_ISSET(ufds[i].fd, &fds_write))
      ufds[i].revents |= POLLOUT;
    if (FD_ISSET(ufds[i].fd, &fds_err))
      ufds[i].revents |= POLLERR;
    if (ufds[i].revents != 0)
      r++;
  }

  return r;
#endif
}
