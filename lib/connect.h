#ifndef __CONNECT_H
#define __CONNECT_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2001, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: connect.h,v 1.4 2001-10-02 09:40:06 bagder Exp $
 *****************************************************************************/

CURLcode Curl_connecthost(struct connectdata *conn,
                          Curl_addrinfo *host, /* connect to this */
                          long port,    /* connect to this port number */
                          int *socket,  /* not set if error is returned */
                          Curl_ipconnect **addr /* the one we used */
                          ); /*  index we used */
#endif
