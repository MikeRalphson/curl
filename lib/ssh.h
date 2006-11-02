#ifndef __SFTP_H
#define __SFTP_H

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: ssh.h,v 1.1 2006-11-02 21:56:43 bagder Exp $
 ***************************************************************************/

#ifdef USE_LIBSSH2

CURLcode Curl_scp_connect(struct connectdata *conn, bool *done);
CURLcode Curl_scp_do(struct connectdata *conn, bool *done);
CURLcode Curl_scp_done(struct connectdata *conn, CURLcode);

int Curl_scp_send(struct connectdata *conn, int sockindex,
                  void *mem, size_t len);
int Curl_scp_recv(struct connectdata *conn, int sockindex,
                  char *mem, size_t len);

#endif

#endif /* USE_LIBSSH2 */
