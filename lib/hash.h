#ifndef __HASH_H
#define __HASH_H
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
 * $Id: hash.h,v 1.8 2002-04-27 13:07:54 bagder Exp $
 *****************************************************************************/

#include "setup.h"

#include <stddef.h>

#include "llist.h"

typedef void (*curl_hash_dtor)(void *);

typedef struct _curl_hash {
  curl_llist     **table;
  curl_hash_dtor   dtor;
  int              slots;
  size_t           size;
} curl_hash;

typedef struct _curl_hash_element {
  void   *ptr;
  char   *key;
  size_t  key_len;
} curl_hash_element;


void Curl_hash_init(curl_hash *, int, curl_hash_dtor);
curl_hash *Curl_hash_alloc(int, curl_hash_dtor);
int Curl_hash_add(curl_hash *, char *, size_t, const void *);
int Curl_hash_delete(curl_hash *h, char *key, size_t key_len);
int Curl_hash_find(curl_hash *, char *, size_t, void **p);
void Curl_hash_apply(curl_hash *h, void *user, void (*cb)(void *, curl_hash_element *));
int Curl_hash_count(curl_hash *h);
void Curl_hash_clean(curl_hash *h);
void Curl_hash_clean_with_criterium(curl_hash *h, void *user, int (*comp)(void *, void *));
void Curl_hash_destroy(curl_hash *h);

#define Curl_hash_update Curl_hash_add

#endif

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
