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
 * $Id: urlglob.c,v 1.11 2001-01-03 09:29:34 bagder Exp $
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include "urlglob.h"

#ifdef MALLOCDEBUG
#include "../lib/memdebug.h"
#endif

int glob_word(URLGlob *, char*, int);

int glob_set(URLGlob *glob, char *pattern, int pos)
{
  /* processes a set expression with the point behind the opening '{'
     ','-separated elements are collected until the next closing '}'
  */
  char* buf = glob->glob_buffer;
  URLPattern *pat;

  pat = (URLPattern*)&glob->pattern[glob->size / 2];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  pat->type = UPTSet;
  pat->content.Set.size = 0;
  pat->content.Set.ptr_s = 0;
  pat->content.Set.elements = (char**)malloc(0);
  ++glob->size;

  while (1) {
    switch (*pattern) {
    case '\0':				/* URL ended while set was still open */
      printf("error: unmatched brace at pos %d\n", pos);
      exit (CURLE_URL_MALFORMAT);
    case '{':
    case '[':				/* no nested expressions at this time */
      printf("error: nested braces not supported %d\n", pos);
      exit (CURLE_URL_MALFORMAT);
    case ',':
    case '}':				/* set element completed */
      *buf = '\0';
      pat->content.Set.elements =
        realloc(pat->content.Set.elements,
                (pat->content.Set.size + 1) * sizeof(char*));
      if (!pat->content.Set.elements) {
	printf("out of memory in set pattern\n");
	exit(CURLE_OUT_OF_MEMORY);
      }
      pat->content.Set.elements[pat->content.Set.size] =
        strdup(glob->glob_buffer);
      ++pat->content.Set.size;

      if (*pattern == '}')		/* entire set pattern completed */
	/* always check for a literal (may be "") between patterns */
	return pat->content.Set.size * glob_word(glob, ++pattern, ++pos);

      buf = glob->glob_buffer;
      ++pattern;
      ++pos;
      break;
    case ']':				/* illegal closing bracket */
      printf("error: illegal pattern at pos %d\n", pos);
      exit (CURLE_URL_MALFORMAT);
    case '\\':				/* escaped character, skip '\' */
      if (*(buf+1) == '\0') {		/* but no escaping of '\0'! */
	printf("error: illegal pattern at pos %d\n", pos);
	exit (CURLE_URL_MALFORMAT);
      }
      ++pattern;
      ++pos;				/* intentional fallthrough */
    default:
      *buf++ = *pattern++;		/* copy character to set element */
      ++pos;
    }
  }
  exit (CURLE_FAILED_INIT);
}

int glob_range(URLGlob *glob, char *pattern, int pos)
{
  /* processes a range expression with the point behind the opening '['
     - char range: e.g. "a-z]", "B-Q]"
     - num range: e.g. "0-9]", "17-2000]"
     - num range with leading zeros: e.g. "001-999]"
     expression is checked for well-formedness and collected until the next ']'
  */
  URLPattern *pat;
  char *c;
  
  pat = (URLPattern*)&glob->pattern[glob->size / 2];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  ++glob->size;

  if (isalpha((int)*pattern)) {		/* character range detected */
    pat->type = UPTCharRange;
    if (sscanf(pattern, "%c-%c]", &pat->content.CharRange.min_c, &pat->content.CharRange.max_c) != 2 ||
	pat->content.CharRange.min_c >= pat->content.CharRange.max_c ||
	pat->content.CharRange.max_c - pat->content.CharRange.min_c > 'z' - 'a') {
      /* the pattern is not well-formed */ 
      printf("error: illegal pattern or range specification after pos %d\n", pos);
      exit (CURLE_URL_MALFORMAT);
    }
    pat->content.CharRange.ptr_c = pat->content.CharRange.min_c;
    /* always check for a literal (may be "") between patterns */
    return (pat->content.CharRange.max_c - pat->content.CharRange.min_c + 1) *
      glob_word(glob, pattern + 4, pos + 4);
  }
  if (isdigit((int)*pattern)) {		/* numeric range detected */
    pat->type = UPTNumRange;
    pat->content.NumRange.padlength = 0;
    if (sscanf(pattern, "%d-%d]", &pat->content.NumRange.min_n, &pat->content.NumRange.max_n) != 2 ||
	pat->content.NumRange.min_n >= pat->content.NumRange.max_n) {
      /* the pattern is not well-formed */ 
      printf("error: illegal pattern or range specification after pos %d\n", pos);
      exit (CURLE_URL_MALFORMAT);
    }
    if (*pattern == '0') {		/* leading zero specified */
      c = pattern;  
      while (isdigit((int)*c++))
	++pat->content.NumRange.padlength;	/* padding length is set for all instances
						   of this pattern */
    }
    pat->content.NumRange.ptr_n = pat->content.NumRange.min_n;
    c = (char*)(strchr(pattern, ']') + 1);	/* continue after next ']' */
    /* always check for a literal (may be "") between patterns */
    return (pat->content.NumRange.max_n - pat->content.NumRange.min_n + 1) *
      glob_word(glob, c, pos + (c - pattern));
  }
  printf("error: illegal character in range specification at pos %d\n", pos);
  exit (CURLE_URL_MALFORMAT);
}

int glob_word(URLGlob *glob, char *pattern, int pos)
{
  /* processes a literal string component of a URL
     special characters '{' and '[' branch to set/range processing functions
   */ 
  char* buf = glob->glob_buffer;
  int litindex;

  while (*pattern != '\0' && *pattern != '{' && *pattern != '[') {
    if (*pattern == '}' || *pattern == ']') {
      printf("illegal character at position %d\n", pos);
      exit (CURLE_URL_MALFORMAT);
    }
    if (*pattern == '\\') {		/* escape character, skip '\' */
      ++pattern;
      ++pos;
      if (*pattern == '\0') {		/* but no escaping of '\0'! */
	printf("illegal character at position %d\n", pos);
	exit (CURLE_URL_MALFORMAT);
      }
    }
    *buf++ = *pattern++;		/* copy character to literal */
    ++pos;
  }
  *buf = '\0';
  litindex = glob->size / 2;
  /* literals 0,1,2,... correspond to size=0,2,4,... */
  glob->literal[litindex] = strdup(glob->glob_buffer);
  ++glob->size;
  if (*pattern == '\0')
    return 1;				/* singular URL processed  */
  if (*pattern == '{') {
    return glob_set(glob, ++pattern, ++pos);	/* process set pattern */
  }
  if (*pattern == '[') {
    return glob_range(glob, ++pattern, ++pos);/* process range pattern */
  }
  printf("internal error\n");
  exit (CURLE_FAILED_INIT);
}

int glob_url(URLGlob** glob, char* url, int *urlnum)
{
  /*
   * We can deal with any-size, just make a buffer with the same length
   * as the specified URL!
   */
  URLGlob *glob_expand;
  char *glob_buffer=(char *)malloc(strlen(url)+1);
  if(NULL == glob_buffer)
    return CURLE_OUT_OF_MEMORY;

  glob_expand = (URLGlob*)malloc(sizeof(URLGlob));
  if(NULL == glob_expand) {
    free(glob_buffer);
    return CURLE_OUT_OF_MEMORY;
  }
  glob_expand->size = 0;
  glob_expand->urllen = strlen(url);
  glob_expand->glob_buffer = glob_buffer;
  *urlnum = glob_word(glob_expand, url, 1);
  *glob = glob_expand;
  return CURLE_OK;
}

void glob_cleanup(URLGlob* glob)
{
  int i, elem;

  for (i = glob->size - 1; i >= 0; --i) {
    if (!(i & 1)) {	/* even indexes contain literals */
      free(glob->literal[i/2]);
    } else {		/* odd indexes contain sets or ranges */
      if (glob->pattern[i/2].type == UPTSet) {
	for (elem = glob->pattern[i/2].content.Set.size - 1; elem >= 0; --elem) {
	  free(glob->pattern[i/2].content.Set.elements[elem]);
	}
	free(glob->pattern[i/2].content.Set.elements);
      }
    }
  }
  free(glob->glob_buffer);
  free(glob);
}

char *next_url(URLGlob *glob)
{
  static int beenhere = 0;
  char *buf = glob->glob_buffer;
  URLPattern *pat;
  char *lit;
  signed int i;
  int carry;

  if (!beenhere)
    beenhere = 1;
  else {
    carry = 1;

    /* implement a counter over the index ranges of all patterns,
       starting with the rightmost pattern */
    for (i = glob->size / 2 - 1; carry && i >= 0; --i) {
      carry = 0;
      pat = &glob->pattern[i];
      switch (pat->type) {
      case UPTSet:
	if (++pat->content.Set.ptr_s == pat->content.Set.size) {
	  pat->content.Set.ptr_s = 0;
	  carry = 1;
	}
	break;
      case UPTCharRange:
	if (++pat->content.CharRange.ptr_c > pat->content.CharRange.max_c) {
	  pat->content.CharRange.ptr_c = pat->content.CharRange.min_c;
	  carry = 1;
	}
	break;
      case UPTNumRange:
	if (++pat->content.NumRange.ptr_n > pat->content.NumRange.max_n) {
	  pat->content.NumRange.ptr_n = pat->content.NumRange.min_n;
	  carry = 1;
	}
	break;
      default:
	printf("internal error: invalid pattern type (%d)\n", pat->type);
	exit (CURLE_FAILED_INIT);
      }
    }
    if (carry)		/* first pattern ptr has run into overflow, done! */
      return NULL;
  }

  for (i = 0; i < glob->size; ++i) {
    if (!(i % 2)) {			/* every other term (i even) is a literal */
      lit = glob->literal[i/2];
      strcpy(buf, lit);
      buf += strlen(lit);
    }
    else {				/* the rest (i odd) are patterns */
      pat = &glob->pattern[i/2];
      switch(pat->type) {
      case UPTSet:
	strcpy(buf, pat->content.Set.elements[pat->content.Set.ptr_s]);
	buf += strlen(pat->content.Set.elements[pat->content.Set.ptr_s]);
	break;
      case UPTCharRange:
	*buf++ = pat->content.CharRange.ptr_c;
	break;
      case UPTNumRange:
	sprintf(buf, "%0*d", pat->content.NumRange.padlength, pat->content.NumRange.ptr_n); 
        buf += strlen(buf); /* make no sprint() return code assumptions */
	break;
      default:
	printf("internal error: invalid pattern type (%d)\n", pat->type);
	exit (CURLE_FAILED_INIT);
      }
    }
  }
  *buf = '\0';
  return strdup(glob->glob_buffer);
}

char *match_url(char *filename, URLGlob *glob)
{
  char *target;
  URLPattern pat;
  int i;
  int allocsize;
  int stringlen=0;
  char numbuf[18];
  char *appendthis;
  size_t appendlen;

  /* We cannot use the glob_buffer for storage here since the filename may
   * be longer than the URL we use. We allocate a good start size, then
   * we need to realloc in case of need.
   */
  allocsize=strlen(filename);
  target = malloc(allocsize);
  if(NULL == target)
    return NULL; /* major failure */

  while (*filename != '\0') {
    if (*filename == '#') {
      if (!isdigit((int)*++filename) ||
	  *filename == '0') {		/* only '#1' ... '#9' allowed */
	/* printf("illegal matching expression\n");
           exit(CURLE_URL_MALFORMAT);*/
        continue;
      }
      i = *filename - '1';
      if (i + 1 > glob->size / 2) {
	/*printf("match against nonexisting pattern\n");
          exit(CURLE_URL_MALFORMAT);*/
        continue;
      }
      pat = glob->pattern[i];
      switch (pat.type) {
      case UPTSet:
	appendthis = pat.content.Set.elements[pat.content.Set.ptr_s];
	appendlen = strlen(pat.content.Set.elements[pat.content.Set.ptr_s]);
	break;
      case UPTCharRange:
        numbuf[0]=pat.content.CharRange.ptr_c;
        numbuf[1]=0;
        appendthis=numbuf;
        appendlen=1;
	break;
      case UPTNumRange:
	sprintf(numbuf, "%0*d", pat.content.NumRange.padlength, pat.content.NumRange.ptr_n);
        appendthis = numbuf;
        appendlen = strlen(numbuf);
	break;
      default:
	printf("internal error: invalid pattern type (%d)\n", pat.type);
        return NULL;
      }
      ++filename;
    }
    else {
      appendthis=filename++;
      appendlen=1;
    }
    if(appendlen + stringlen >= allocsize) {
      char *newstr;
      allocsize = (appendlen + stringlen)*2;
      newstr=realloc(target, allocsize);
      if(NULL ==newstr) {
        free(target);
        return NULL;
      }
      target=newstr;
    }
    memcpy(&target[stringlen], appendthis, appendlen);
    stringlen += appendlen;
  }
  target[stringlen]= '\0';
  return target;
}
