#ifndef __STREQUAL_H
#define __STREQUAL_H
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
 * $Id: strequal.h,v 1.5 2001-01-05 10:11:42 bagder Exp $
 *****************************************************************************/
int Curl_strequal(const char *first, const char *second);
int Curl_strnequal(const char *first, const char *second, size_t max);

#define strequal(a,b) Curl_strequal(a,b)
#define strnequal(a,b,c) Curl_strnequal(a,b,c)

#endif
