#ifndef __URLGLOB_H
#define __URLGLOB_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source: /cvsroot/curl/curl/src/urlglob.h,v $
 * $Revision: 1.4 $
 * $Date: 2000-11-09 12:51:43 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/
typedef enum {UPTSet=1,UPTCharRange,UPTNumRange} URLPatternType;

typedef struct {
  URLPatternType type;
  union {
    struct {
      char **elements;
      short size;
      short ptr_s;
    } Set;
    struct {
      char min_c, max_c;
      char ptr_c;
    } CharRange;
    struct {
      int min_n, max_n;
      short padlength;
      int ptr_n;
    } NumRange ;
  } content;
} URLPattern;

typedef struct {
  char* literal[10];
  URLPattern pattern[9];
  int size;
} URLGlob;

int glob_url(URLGlob**, char*, int *);
char* next_url(URLGlob*);
char* match_url(char*, URLGlob); 

#endif
