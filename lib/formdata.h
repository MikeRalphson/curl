#ifndef __FORMDATA_H
#define __FORMDATA_H

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
 * $Id: formdata.h,v 1.4 2001-01-03 09:29:34 bagder Exp $
 *****************************************************************************/
/* plain and simple linked list with lines to send */
struct FormData {
  struct FormData *next;
  char *line;
  long length;
};

struct Form {
  struct FormData *data; /* current form line to send */
  int sent; /* number of bytes of the current line that has already
	       been sent in a previous invoke */
};

int FormParse(char *string,
	      struct HttpPost **httppost,
	      struct HttpPost **last_post);

int FormInit(struct Form *form, struct FormData *formdata );

struct FormData *getFormData(struct HttpPost *post,
			     int *size);

/* fread() emulation */
int FormReader(char *buffer,
	       size_t size,
	       size_t nitems,
	       FILE *mydata);

char *MakeFormBoundary(void);

void FormFree(struct FormData *);

#endif
