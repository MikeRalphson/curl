#ifndef __NETRC_H
#define __NETRC_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: netrc.h,v 1.7 2002-05-21 22:17:19 bagder Exp $
 *****************************************************************************/
int Curl_parsenetrc(char *host,
                    char *login,
                    char *password);
  /* Assume: password[0]=0, host[0] != 0.
   * If login[0] = 0, search for login and password within a machine section
   * in the netrc.
   * If login[0] != 0, search for password within machine and login.
   */
#endif
