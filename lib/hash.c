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
 * $Id: hash.c,v 1.9 2002-04-17 20:13:55 bumblebury Exp $
 *****************************************************************************/

#include "setup.h"

#include <string.h>
#include <stdlib.h>
#include "hash.h"
#include "llist.h"

#ifdef MALLOCDEBUG
/* this must be the last include file */
#include "memdebug.h"
#endif


/* {{{ static unsigned long _hash_str (const char *, size_t)
 */
static unsigned long
_hash_str (const char *key, size_t key_length)
{
  char *end = (char *) key + key_length;
  unsigned long h = 5381;

  while (key < end) {
    h += h << 5;
    h ^= (unsigned long) *key++;
  }

  return h;
}
/* }}} */

/* {{{ static void _hash_element_dtor (void *, void *)
 */
static void 
_hash_element_dtor (void *user, void *element)
{
  curl_hash         *h = (curl_hash *) user;
  curl_hash_element *e = (curl_hash_element *) element;

  if (e->key) {
    free(e->key);
  }

  h->dtor(e->ptr);

  free(e);
}
/* }}} */

/* {{{ void curl_hash_init (curl_hash *, int, curl_hash_dtor)
 */
void 
curl_hash_init (curl_hash *h, int slots, curl_hash_dtor dtor)
{
  int i;

  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;  

  h->table = (curl_llist **) malloc(slots * sizeof(curl_llist *));
  for (i = 0; i < slots; ++i) {
    h->table[i] = curl_llist_alloc((curl_llist_dtor) _hash_element_dtor);
  }
}
/* }}} */

/* {{{ curl_hash *curl_hash_alloc (int, curl_hash_dtor)
 */
curl_hash *
curl_hash_alloc (int slots, curl_hash_dtor dtor)
{
  curl_hash *h;

  h = (curl_hash *) malloc(sizeof(curl_hash));
  if (NULL == h)
    return NULL;

  curl_hash_init(h, slots, dtor);

  return h;
}
/* }}} */

/* {{{ static int _hash_key_compare (char *, size_t, char *, size_t)
 */
static int 
_hash_key_compare (char *key1, size_t key1_len, char *key2, size_t key2_len)
{
  if (key1_len == key2_len && 
      *key1 == *key2 &&
      memcmp(key1, key2, key1_len) == 0) {
    return 1;
  }

  return 0;
}
/* }}} */

/* {{{ static int _mk_hash_element (curl_hash_element **, char *, size_t, const void *)
 */
static int
_mk_hash_element (curl_hash_element **e, char *key, size_t key_len, const void *p)
{
  *e = (curl_hash_element *) malloc(sizeof(curl_hash_element));
  (*e)->key = strdup(key);
  (*e)->key_len = key_len;
  (*e)->ptr = (void *) p;

  return 0;
}
/* }}} */

#define find_slot(__h, __k, __k_len) (_hash_str(__k, __k_len) % (__h)->slots)

#define FETCH_LIST \
  curl_llist *l = h->table[find_slot(h, key, key_len)]


/* {{{ int curl_hash_add (curl_hash *, char *, size_t, const void *)
 */
int 
curl_hash_add (curl_hash *h, char *key, size_t key_len, const void *p)
{
  curl_hash_element  *he;
  curl_llist_element *le;
  FETCH_LIST;

  for (le = CURL_LLIST_HEAD(l);
       le != NULL;
       le = CURL_LLIST_NEXT(le)) {
    he = (curl_hash_element *) CURL_LLIST_VALP(le);
    if (_hash_key_compare(he->key, he->key_len, key, key_len)) {
      h->dtor(he->ptr);
      he->ptr = (void *) p;
      return 1;
    }
  }

  if (_mk_hash_element(&he, key, key_len, p) != 0) 
    return 0;

  if (curl_llist_insert_next(l, CURL_LLIST_TAIL(l), he)) {
    ++h->size;
    return 1;
  }

  return 0;
}
/* }}} */

/* {{{ int curl_hash_delete (curl_hash *, char *, size_t)
 */
int 
curl_hash_delete(curl_hash *h, char *key, size_t key_len)
{
  curl_hash_element  *he;
  curl_llist_element *le;
  FETCH_LIST;

  for (le = CURL_LLIST_HEAD(l);
       le != NULL;
       le = CURL_LLIST_NEXT(le)) {
    he = CURL_LLIST_VALP(le);
    if (_hash_key_compare(he->key, he->key_len, key, key_len)) {
      curl_llist_remove(l, le, (void *) h);
      --h->size;
      return 1;
    }
  }

  return 0;
}
/* }}} */

/* {{{ int curl_hash_find (curl_hash *, char *, size_t, void **)
 */
int 
curl_hash_find(curl_hash *h, char *key, size_t key_len, void **p)
{
  curl_llist_element *le;
  curl_hash_element  *he;
  FETCH_LIST;

  for (le = CURL_LLIST_HEAD(l);
       le != NULL;
       le = CURL_LLIST_NEXT(le)) {
    he = CURL_LLIST_VALP(le);
    if (_hash_key_compare(he->key, he->key_len, key, key_len)) {
      *p = he->ptr;
      return 1;
    }
  }

  return 0;
}
/* }}} */

/* {{{ void curl_hash_apply (curl_hash *, void *, void (*)(void *, curl_hash_element *))
 */
void 
curl_hash_apply(curl_hash *h, void *user, void (*cb)(void *, curl_hash_element *))
{
  curl_llist_element  *le;
  int                  i;

  for (i = 0; i < h->slots; ++i) {
    for (le = CURL_LLIST_HEAD(h->table[i]); le != NULL; le = CURL_LLIST_NEXT(le)) {
      cb(user, (curl_hash_element *) CURL_LLIST_VALP(le));
    }
  }
}
/* }}} */

/* {{{ void curl_hash_clean (curl_hash *)
 */
void
curl_hash_clean(curl_hash *h)
{
  int i;

  for (i = 0; i < h->slots; ++i) {
    curl_llist_destroy(h->table[i], (void *) h);
  }

  free(h->table);
}
/* }}} */

/* {{{ void curl_hash_clean_with_criterium (curl_hash *, void *, int (*)(void *, void *))
 */
void
curl_hash_clean_with_criterium(curl_hash *h, void *user, int (*comp)(void *, void *))
{
  curl_llist_element *le;
  int i;

  for (i = 0; i < h->slots; ++i) {
    for (le = CURL_LLIST_HEAD(h->table[i]);
         le != NULL;
         le = CURL_LLIST_NEXT(le)) {
      if (comp(user, ((curl_hash_element *) CURL_LLIST_VALP(le))->ptr)) {
        curl_llist_remove(h->table[i], le, (void *) h);
        --h->size;
      }
    }
  }
}

/* {{{ int curl_hash_count (curl_hash *)
 */
int 
curl_hash_count(curl_hash *h)
{
  return h->size;
}
/* }}} */

/* {{{ void curl_hash_destroy (curl_hash *)
 */
void 
curl_hash_destroy(curl_hash *h)
{
  if (!h)
    return;

  curl_hash_clean(h);
  free(h);
}
/* }}} */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
