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
 * $Id: formdata.c,v 1.59 2004-05-04 08:24:13 bagder Exp $
 ***************************************************************************/

/*
  Debug the form generator stand-alone by compiling this source file with:

  gcc -DHAVE_CONFIG_H -I../ -g -D_FORM_DEBUG -o formdata -I../include formdata.c strequal.c

  run the 'formdata' executable the output should end with:
  All Tests seem to have worked ...
  and the following parts should be there:

Content-Disposition: form-data; name="simple_COPYCONTENTS"
value for simple COPYCONTENTS

Content-Disposition: form-data; name="COPYCONTENTS_+_CONTENTTYPE"
Content-Type: image/gif
value for COPYCONTENTS + CONTENTTYPE

Content-Disposition: form-data; name="PRNAME_+_NAMELENGTH_+_COPYNAME_+_CONTENTSLENGTH"
vlue for PTRNAME + NAMELENGTH + COPYNAME + CONTENTSLENGTH
(or you might see P^@RNAME and v^@lue at the start)

Content-Disposition: form-data; name="simple_PTRCONTENTS"
value for simple PTRCONTENTS

Content-Disposition: form-data; name="PTRCONTENTS_+_CONTENTSLENGTH"
vlue for PTRCONTENTS + CONTENTSLENGTH
(or you might see v^@lue at the start)

Content-Disposition: form-data; name="PTRCONTENTS_+_CONTENTSLENGTH_+_CONTENTTYPE"
Content-Type: text/plain
vlue for PTRCOTNENTS + CONTENTSLENGTH + CONTENTTYPE
(or you might see v^@lue at the start)

Content-Disposition: form-data; name="FILE1_+_CONTENTTYPE"; filename="inet_ntoa_r.h"
Content-Type: text/html
...

Content-Disposition: form-data; name="FILE1_+_FILE2"
Content-Type: multipart/mixed, boundary=curlz1s0dkticx49MV1KGcYP5cvfSsz
...
Content-Disposition: attachment; filename="inet_ntoa_r.h"
Content-Type: text/plain
...
Content-Disposition: attachment; filename="Makefile.b32.resp"
Content-Type: text/plain
...

Content-Disposition: form-data; name="FILE1_+_FILE2_+_FILE3"
Content-Type: multipart/mixed, boundary=curlirkYPmPwu6FrJ1vJ1u1BmtIufh1
...
Content-Disposition: attachment; filename="inet_ntoa_r.h"
Content-Type: text/plain
...
Content-Disposition: attachment; filename="Makefile.b32.resp"
Content-Type: text/plain
...
Content-Disposition: attachment; filename="inet_ntoa_r.h"
Content-Type: text/plain
...


Content-Disposition: form-data; name="ARRAY: FILE1_+_FILE2_+_FILE3"
Content-Type: multipart/mixed, boundary=curlirkYPmPwu6FrJ1vJ1u1BmtIufh1
...
Content-Disposition: attachment; filename="inet_ntoa_r.h"
Content-Type: text/plain
...
Content-Disposition: attachment; filename="Makefile.b32.resp"
Content-Type: text/plain
...
Content-Disposition: attachment; filename="inet_ntoa_r.h"
Content-Type: text/plain
...

Content-Disposition: form-data; name="FILECONTENT"
...

 */

#include "setup.h"

#ifndef CURL_DISABLE_HTTP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <time.h>

#include <curl/curl.h>
#include "formdata.h"

#include "strequal.h"

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

/* Length of the random boundary string. */
#define BOUNDARY_LENGTH 40

/* What kind of Content-Type to use on un-specified files with unrecognized
   extensions. */
#define HTTPPOST_CONTENTTYPE_DEFAULT "application/octet-stream"

/* This is a silly duplicate of the function in main.c to enable this source
   to compile stand-alone for better debugging */
static void GetStr(char **string,
		   const char *value)
{
  if(*string)
    free(*string);
  *string = strdup(value);
}

/***************************************************************************
 *
 * FormParse()
 *	
 * Reads a 'name=value' paramter and builds the appropriate linked list.
 *
 * Specify files to upload with 'name=@filename'. Supports specified
 * given Content-Type of the files. Such as ';type=<content-type>'.
 *
 * You may specify more than one file for a single name (field). Specify
 * multiple files by writing it like:
 *
 * 'name=@filename,filename2,filename3'
 *
 * If you want content-types specified for each too, write them like:
 *
 * 'name=@filename;type=image/gif,filename2,filename3'
 *
 ***************************************************************************/

#define FORM_FILE_SEPARATOR ','
#define FORM_TYPE_SEPARATOR ';'

/***************************************************************************
 *
 * AddHttpPost()
 *	
 * Adds a HttpPost structure to the list, if parent_post is given becomes
 * a subpost of parent_post instead of a direct list element.
 *
 * Returns newly allocated HttpPost on success and NULL if malloc failed.
 *
 ***************************************************************************/
static struct curl_httppost *
AddHttpPost(char * name, size_t namelength,
            char * value, size_t contentslength,
            char * buffer, size_t bufferlength,
            char *contenttype,
            long flags,
            struct curl_slist* contentHeader,
            char *showfilename,
            struct curl_httppost *parent_post,
            struct curl_httppost **httppost,
            struct curl_httppost **last_post)
{
  struct curl_httppost *post;
  post = (struct curl_httppost *)malloc(sizeof(struct curl_httppost));
  if(post) {
    memset(post, 0, sizeof(struct curl_httppost));
    post->name = name;
    post->namelength = (long)(name?(namelength?namelength:strlen(name)):0);
    post->contents = value;
    post->contentslength = (long)contentslength;
    post->buffer = buffer;
    post->bufferlength = (long)bufferlength;
    post->contenttype = contenttype;
    post->contentheader = contentHeader;
    post->showfilename = showfilename;
    post->flags = flags;
  }
  else
    return NULL;
  
  if (parent_post) {
    /* now, point our 'more' to the original 'more' */
    post->more = parent_post->more;
    
    /* then move the original 'more' to point to ourselves */
    parent_post->more = post;	         
  }
  else {
    /* make the previous point to this */
    if(*last_post)
      (*last_post)->next = post;
    else
      (*httppost) = post;
    
    (*last_post) = post;  
  }
  return post;
}

/***************************************************************************
 *
 * AddFormInfo()
 *	
 * Adds a FormInfo structure to the list presented by parent_form_info.
 *
 * Returns newly allocated FormInfo on success and NULL if malloc failed/
 * parent_form_info is NULL.
 *
 ***************************************************************************/
static FormInfo * AddFormInfo(char *value,
                              char *contenttype,
                              FormInfo *parent_form_info)
{
  FormInfo *form_info;
  form_info = (FormInfo *)malloc(sizeof(FormInfo));
  if(form_info) {
    memset(form_info, 0, sizeof(FormInfo));
    if (value)
      form_info->value = value;
    if (contenttype)
      form_info->contenttype = contenttype;
    form_info->flags = HTTPPOST_FILENAME;
  }
  else
    return NULL;
  
  if (parent_form_info) {
    /* now, point our 'more' to the original 'more' */
    form_info->more = parent_form_info->more;
    
    /* then move the original 'more' to point to ourselves */
    parent_form_info->more = form_info;
  }
  else
    return NULL;

  return form_info;
}

/***************************************************************************
 *
 * ContentTypeForFilename()
 *	
 * Provides content type for filename if one of the known types (else
 * (either the prevtype or the default is returned).
 *
 * Returns some valid contenttype for filename.
 *
 ***************************************************************************/
static const char * ContentTypeForFilename (const char *filename,
					    const char *prevtype)
{
  const char *contenttype = NULL;
  unsigned int i;
  /*
   * No type was specified, we scan through a few well-known
   * extensions and pick the first we match!
   */
  struct ContentType {
    const char *extension;
    const char *type;
  };
  static struct ContentType ctts[]={
    {".gif",  "image/gif"},
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".txt",  "text/plain"},
    {".html", "text/html"}
  };
  
  if(prevtype)
    /* default to the previously set/used! */
    contenttype = prevtype;
  else
    /* It seems RFC1867 defines no Content-Type to default to
       text/plain so we don't actually need to set this: */
    contenttype = HTTPPOST_CONTENTTYPE_DEFAULT;
  
  for(i=0; i<sizeof(ctts)/sizeof(ctts[0]); i++) {
    if(strlen(filename) >= strlen(ctts[i].extension)) {
      if(strequal(filename +
		  strlen(filename) - strlen(ctts[i].extension),
		  ctts[i].extension)) {
	contenttype = ctts[i].type;
	break;
      }	      
    }
  }
  /* we have a contenttype by now */
  return contenttype;
}

/***************************************************************************
 *
 * AllocAndCopy()
 *	
 * Copies the data currently available under *buffer using newly allocated
 * buffer (that becomes *buffer). Uses buffer_length if not null, else
 * uses strlen to determine the length of the buffer to be copied
 *
 * Returns 0 on success and 1 if the malloc failed.
 *
 ***************************************************************************/
static int AllocAndCopy(char **buffer, size_t buffer_length)
{
  const char *src = *buffer;
  size_t length;
  bool add = FALSE;
  if (buffer_length)
    length = buffer_length;
  else {
    length = strlen(*buffer);
    add = TRUE;
  }
  *buffer = (char*)malloc(length+add);
  if (!*buffer)
    return 1;
  memcpy(*buffer, src, length);
  /* if length unknown do null termination */
  if (add)
    (*buffer)[length] = '\0';
  return 0;
}

/***************************************************************************
 *
 * FormAdd()
 *	
 * Stores a 'name=value' formpost parameter and builds the appropriate
 * linked list.
 *
 * Has two principal functionalities: using files and byte arrays as
 * post parts. Byte arrays are either copied or just the pointer is stored
 * (as the user requests) while for files only the filename and not the
 * content is stored.
 *
 * While you may have only one byte array for each name, multiple filenames
 * are allowed (and because of this feature CURLFORM_END is needed after
 * using CURLFORM_FILE).
 *
 * Examples:
 *
 * Simple name/value pair with copied contents:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_COPYCONTENTS, "value", CURLFORM_END);
 *
 * name/value pair where only the content pointer is remembered:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_PTRCONTENTS, ptr, CURLFORM_CONTENTSLENGTH, 10, CURLFORM_END);
 * (if CURLFORM_CONTENTSLENGTH is missing strlen () is used)
 *
 * storing a filename (CONTENTTYPE is optional!):
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_FILE, "filename1", CURLFORM_CONTENTTYPE, "plain/text",
 * CURLFORM_END);
 *
 * storing multiple filenames:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_FILE, "filename1", CURLFORM_FILE, "filename2", CURLFORM_END);
 *
 * Returns:
 * CURL_FORMADD_OK             on success
 * CURL_FORMADD_MEMORY         if the FormInfo allocation fails
 * CURL_FORMADD_OPTION_TWICE   if one option is given twice for one Form
 * CURL_FORMADD_NULL           if a null pointer was given for a char
 * CURL_FORMADD_MEMORY         if the allocation of a FormInfo struct failed
 * CURL_FORMADD_UNKNOWN_OPTION if an unknown option was used
 * CURL_FORMADD_INCOMPLETE     if the some FormInfo is not complete (or an error)
 * CURL_FORMADD_MEMORY         if a HttpPost struct cannot be allocated
 * CURL_FORMADD_MEMORY         if some allocation for string copying failed.
 * CURL_FORMADD_ILLEGAL_ARRAY  if an illegal option is used in an array
 *
 ***************************************************************************/

static
CURLFORMcode FormAdd(struct curl_httppost **httppost,
                     struct curl_httppost **last_post,
                     va_list params)
{
  FormInfo *first_form, *current_form, *form;
  CURLFORMcode return_value = CURL_FORMADD_OK;
  const char *prevtype = NULL;
  struct curl_httppost *post = NULL;
  CURLformoption option;
  struct curl_forms *forms = NULL;
  char *array_value=NULL; /* value read from an array */

  /* This is a state variable, that if TRUE means that we're parsing an
     array that we got passed to us. If FALSE we're parsing the input
     va_list arguments. */
  bool array_state = FALSE;

  /*
   * We need to allocate the first struct to fill in.
   */
  first_form = (FormInfo *)malloc(sizeof(struct FormInfo));
  if(first_form) {
    memset(first_form, 0, sizeof(FormInfo));
    current_form = first_form;
  }
  else
    return CURL_FORMADD_MEMORY;

  /*
   * Loop through all the options set.
   */
  while (1) {

    /* break if we have an error to report */
    if (return_value != CURL_FORMADD_OK)
      break;

    /* first see if we have more parts of the array param */
    if ( array_state ) {
      /* get the upcoming option from the given array */
      option = forms->option;
      array_value = (char *)forms->value;

      forms++; /* advance this to next entry */
      if (CURLFORM_END == option) {
        /* end of array state */
        array_state = FALSE;
        continue;
      }
    }
    else {
      /* This is not array-state, get next option */
      option = va_arg(params, CURLformoption);
      if (CURLFORM_END == option)
        break;
    }

    switch (option) {
    case CURLFORM_ARRAY:
      if(array_state)
        /* we don't support an array from within an array */
        return_value = CURL_FORMADD_ILLEGAL_ARRAY;
      else {
        forms = va_arg(params, struct curl_forms *);
        if (forms)
          array_state = TRUE;
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

      /*
       * Set the Name property.
       */
    case CURLFORM_PTRNAME:
      current_form->flags |= HTTPPOST_PTRNAME; /* fall through */
    case CURLFORM_COPYNAME:
      if (current_form->name)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *name = array_state?
          array_value:va_arg(params, char *);
        if (name)
          current_form->name = name; /* store for the moment */
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;
    case CURLFORM_NAMELENGTH:
      if (current_form->namelength)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else
        current_form->namelength =
          array_state?(long)array_value:va_arg(params, long);
      break;

      /*
       * Set the contents property.
       */
    case CURLFORM_PTRCONTENTS:
      current_form->flags |= HTTPPOST_PTRCONTENTS; /* fall through */
    case CURLFORM_COPYCONTENTS:
      if (current_form->value)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *value =
          array_state?array_value:va_arg(params, char *);
        if (value)
          current_form->value = value; /* store for the moment */
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;
    case CURLFORM_CONTENTSLENGTH:
      if (current_form->contentslength)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else
        current_form->contentslength =
          array_state?(long)array_value:va_arg(params, long);
      break;

      /* Get contents from a given file name */
    case CURLFORM_FILECONTENT:
      if (current_form->flags != 0)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *filename = array_state?
          array_value:va_arg(params, char *);
        if (filename) {
          current_form->value = strdup(filename);
          current_form->flags |= HTTPPOST_READFILE;
        }
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

      /* We upload a file */
    case CURLFORM_FILE:
      {
        char *filename = array_state?array_value:
          va_arg(params, char *);

        if (current_form->value) {
          if (current_form->flags & HTTPPOST_FILENAME) {
            if (filename) {
              if (!(current_form = AddFormInfo(strdup(filename),
                                               NULL, current_form)))
                return_value = CURL_FORMADD_MEMORY;
            }
            else
              return_value = CURL_FORMADD_NULL;
          }
          else
            return_value = CURL_FORMADD_OPTION_TWICE;
        }
        else {
          if (filename)
            current_form->value = strdup(filename);
          else
            return_value = CURL_FORMADD_NULL;
          current_form->flags |= HTTPPOST_FILENAME;
        }
        break;
      }

    case CURLFORM_BUFFER:
      {
        char *filename = array_state?array_value:
          va_arg(params, char *);

        if (current_form->value) {
          if (current_form->flags & HTTPPOST_BUFFER) {
            if (filename) {
              if (!(current_form = AddFormInfo(strdup(filename),
                                               NULL, current_form)))
                return_value = CURL_FORMADD_MEMORY;
            }
            else
              return_value = CURL_FORMADD_NULL;
          }
          else
            return_value = CURL_FORMADD_OPTION_TWICE;
        }
        else {
          if (filename)
            current_form->value = strdup(filename);
          else
            return_value = CURL_FORMADD_NULL;
          current_form->flags |= HTTPPOST_BUFFER;
        }
        break;
      }
      
    case CURLFORM_BUFFERPTR:
        current_form->flags |= HTTPPOST_PTRBUFFER;
      if (current_form->buffer)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *buffer =
          array_state?array_value:va_arg(params, char *);
        if (buffer)
          current_form->buffer = buffer; /* store for the moment */
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_BUFFERLENGTH:
      if (current_form->bufferlength)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else
        current_form->bufferlength =
          array_state?(long)array_value:va_arg(params, long);
      break;

    case CURLFORM_CONTENTTYPE:
      {
        char *contenttype =
          array_state?array_value:va_arg(params, char *);
        if (current_form->contenttype) {
          if (current_form->flags & HTTPPOST_FILENAME) {
            if (contenttype) {
              if (!(current_form = AddFormInfo(NULL,
                                               strdup(contenttype),
                                               current_form)))
                return_value = CURL_FORMADD_MEMORY;
            }
	    else
	      return_value = CURL_FORMADD_NULL;
          }
          else
            return_value = CURL_FORMADD_OPTION_TWICE;
        }
        else {
	  if (contenttype)
	    current_form->contenttype = strdup(contenttype);
	  else
	    return_value = CURL_FORMADD_NULL;
	}
        break;
      }
    case CURLFORM_CONTENTHEADER:
      {
        /* this "cast increases required alignment of target type" but
           we consider it OK anyway */
        struct curl_slist* list = array_state?
          (struct curl_slist*)array_value:
          va_arg(params, struct curl_slist*);
        
        if( current_form->contentheader )
          return_value = CURL_FORMADD_OPTION_TWICE;
        else
          current_form->contentheader = list;
        
        break;
      }
    case CURLFORM_FILENAME:
      {
        char *filename = array_state?array_value:
          va_arg(params, char *);
        if( current_form->showfilename )
          return_value = CURL_FORMADD_OPTION_TWICE;
        else
          current_form->showfilename = strdup(filename);
        break;
      }
    default:
      return_value = CURL_FORMADD_UNKNOWN_OPTION;
    }
  }

  if(CURL_FORMADD_OK == return_value) {
    /* go through the list, check for copleteness and if everything is
     * alright add the HttpPost item otherwise set return_value accordingly */
    
    post = NULL;
    for(form = first_form;
        form != NULL;
        form = form->more) {
      if ( ((!form->name || !form->value) && !post) ||
           ( (form->contentslength) &&
             (form->flags & HTTPPOST_FILENAME) ) ||
           ( (form->flags & HTTPPOST_FILENAME) &&
             (form->flags & HTTPPOST_PTRCONTENTS) ) ||

           ( (!form->buffer) &&
             (form->flags & HTTPPOST_BUFFER) &&
             (form->flags & HTTPPOST_PTRBUFFER) ) ||

           ( (form->flags & HTTPPOST_READFILE) &&
             (form->flags & HTTPPOST_PTRCONTENTS) )
           ) {
        return_value = CURL_FORMADD_INCOMPLETE;
        break;
      }
      else {
        if ( ((form->flags & HTTPPOST_FILENAME) ||
              (form->flags & HTTPPOST_BUFFER)) &&
             !form->contenttype ) {
          /* our contenttype is missing */
          form->contenttype
            = strdup(ContentTypeForFilename(form->value, prevtype));
        }
        if ( !(form->flags & HTTPPOST_PTRNAME) &&
             (form == first_form) ) {
          /* copy name (without strdup; possibly contains null characters) */
          if (AllocAndCopy(&form->name, form->namelength)) {
            return_value = CURL_FORMADD_MEMORY;
            break;
          }
        }
        if ( !(form->flags & HTTPPOST_FILENAME) &&
             !(form->flags & HTTPPOST_READFILE) && 
             !(form->flags & HTTPPOST_PTRCONTENTS) &&
             !(form->flags & HTTPPOST_PTRBUFFER) ) {

          /* copy value (without strdup; possibly contains null characters) */
          if (AllocAndCopy(&form->value, form->contentslength)) {
            return_value = CURL_FORMADD_MEMORY;
            break;
          }
        }
        post = AddHttpPost(form->name, form->namelength,
                           form->value, form->contentslength,
                           form->buffer, form->bufferlength,
                           form->contenttype, form->flags,
                           form->contentheader, form->showfilename,
                           post, httppost,
                           last_post);
        
        if(!post)
          return_value = CURL_FORMADD_MEMORY;

        if (form->contenttype)
          prevtype = form->contenttype;
      }
    }
  }

  /* always delete the allocated memory before returning */
  form = first_form;
  while (form != NULL) {
    FormInfo *delete_form;
    
    delete_form = form;
    form = form->more;
    free (delete_form);
  }

  return return_value;
}

/*
 * curl_formadd() is a public API to add a section to the multipart formpost.
 */

CURLFORMcode curl_formadd(struct curl_httppost **httppost,
                          struct curl_httppost **last_post,
                          ...)
{
  va_list arg;
  CURLFORMcode result;
  va_start(arg, last_post);
  result = FormAdd(httppost, last_post, arg);
  va_end(arg);
  return result;
}

/*
 * AddFormData() adds a chunk of data to the FormData linked list.
 */
static size_t AddFormData(struct FormData **formp,
                          const void *line,
                          size_t length)
{
  struct FormData *newform = (struct FormData *)
    malloc(sizeof(struct FormData));
  newform->next = NULL;

  /* we make it easier for plain strings: */
  if(!length)
    length = strlen((char *)line);

  newform->line = (char *)malloc(length+1);
  memcpy(newform->line, line, length);
  newform->length = length;
  newform->line[length]=0; /* zero terminate for easier debugging */
  
  if(*formp) {
    (*formp)->next = newform;
    *formp = newform;
  }
  else
    *formp = newform;

  return length;
}

/*
 * AddFormDataf() adds printf()-style formatted data to the formdata chain.
 */

static size_t AddFormDataf(struct FormData **formp,
                           const char *fmt, ...)
{
  char s[4096];
  va_list ap;
  va_start(ap, fmt);
  vsprintf(s, fmt, ap);
  va_end(ap);

  return AddFormData(formp, s, 0);
}

/*
 * Curl_FormBoundary() creates a suitable boundary string and returns an
 * allocated one.
 */
char *Curl_FormBoundary(void)
{
  char *retstring;
  static int randomizer=0; /* this is just so that two boundaries within
			      the same form won't be identical */
  size_t i;

  static char table16[]="abcdef0123456789";

  retstring = (char *)malloc(BOUNDARY_LENGTH+1);

  if(!retstring)
    return NULL; /* failed */

  srand(time(NULL)+randomizer++); /* seed */

  strcpy(retstring, "----------------------------");

  for(i=strlen(retstring); i<BOUNDARY_LENGTH; i++)
    retstring[i] = table16[rand()%16];

  /* 28 dashes and 12 hexadecimal digits makes 12^16 (184884258895036416)
     combinations */
  retstring[BOUNDARY_LENGTH]=0; /* zero terminate */

  return retstring;
}

/*
 * Curl_formclean() is used from http.c, this cleans a built FormData linked
 * list
 */ 
void Curl_formclean(struct FormData *form)
{
  struct FormData *next;

  do {
    next=form->next;  /* the following form line */
    free(form->line); /* free the line */
    free(form);       /* free the struct */
  
  } while((form=next)); /* continue */
}

/*
 * curl_formfree() is an external function to free up a whole form post
 * chain
 */
void curl_formfree(struct curl_httppost *form)
{
  struct curl_httppost *next;

  if(!form)
    /* no form to free, just get out of this */
    return;

  do {
    next=form->next;  /* the following form line */

    /* recurse to sub-contents */
    if(form->more)
      curl_formfree(form->more);

    if( !(form->flags & HTTPPOST_PTRNAME) && form->name)
      free(form->name); /* free the name */
    if( !(form->flags & HTTPPOST_PTRCONTENTS) && form->contents)
      free(form->contents); /* free the contents */
    if(form->contenttype)
      free(form->contenttype); /* free the content type */
    if(form->showfilename)
      free(form->showfilename); /* free the faked file name */
    free(form);       /* free the struct */

  } while((form=next)); /* continue */
}

/*
 * Curl_getFormData() converts a linked list of "meta data" into a complete
 * (possibly huge) multipart formdata. The input list is in 'post', while the
 * output resulting linked lists gets stored in '*finalform'. *sizep will get
 * the total size of the whole POST.
 */

CURLcode Curl_getFormData(struct FormData **finalform,
                          struct curl_httppost *post,
                          curl_off_t *sizep)
{
  struct FormData *form = NULL;
  struct FormData *firstform;
  struct curl_httppost *file;
  CURLcode result = CURLE_OK;

  size_t size =0;
  char *boundary;
  char *fileboundary=NULL;
  struct curl_slist* curList;

  *finalform=NULL; /* default form is empty */

  if(!post)
    return result; /* no input => no output! */

  boundary = Curl_FormBoundary();
  
  /* Make the first line of the output */
  AddFormDataf(&form,
               "Content-Type: multipart/form-data;"
               " boundary=%s\r\n",
               boundary);
  /* we DO NOT count that line since that'll be part of the header! */

  firstform = form;
  
  do {

    if(size)
      size += AddFormDataf(&form, "\r\n");

    /* boundary */
    size += AddFormDataf(&form, "--%s\r\n", boundary);

    size += AddFormData(&form,
                        "Content-Disposition: form-data; name=\"", 0);

    size += AddFormData(&form, post->name, post->namelength);

    size += AddFormData(&form, "\"", 0);

    if(post->more) {
      /* If used, this is a link to more file names, we must then do
         the magic to include several files with the same field name */

      fileboundary = Curl_FormBoundary();

      size += AddFormDataf(&form,
                           "\r\nContent-Type: multipart/mixed,"
                           " boundary=%s\r\n",
                           fileboundary);
    }

    file = post;

    do {

      /* If 'showfilename' is set, that is a faked name passed on to us
         to use to in the formpost. If that is not set, the actually used
         local file name should be added. */

      if(post->more) {
        /* if multiple-file */
        size += AddFormDataf(&form,
                             "\r\n--%s\r\nContent-Disposition: "
                             "attachment; filename=\"%s\"",
                             fileboundary,
                             (file->showfilename?file->showfilename:
                              file->contents));
      }
      else if((post->flags & HTTPPOST_FILENAME) ||
              (post->flags & HTTPPOST_BUFFER)) {

        size += AddFormDataf(&form,
                             "; filename=\"%s\"",
                             (post->showfilename?post->showfilename:
                              post->contents));
      }
      
      if(file->contenttype) {
        /* we have a specified type */
        size += AddFormDataf(&form,
                             "\r\nContent-Type: %s",
                             file->contenttype);
      }

      curList = file->contentheader;
      while( curList ) {
        /* Process the additional headers specified for this form */
        size += AddFormDataf( &form, "\r\n%s", curList->data );
        curList = curList->next;
      }

#if 0
      /* The header Content-Transfer-Encoding: seems to confuse some receivers
       * (like the built-in PHP engine). While I can't see any reason why it
       * should, I can just as well skip this to the benefit of the users who
       * are using such confused receivers.
       */
      
      if(file->contenttype &&
         !checkprefix("text/", file->contenttype)) {
        /* this is not a text content, mention our binary encoding */
        size += AddFormData(&form, "\r\nContent-Transfer-Encoding: binary", 0);
      }
#endif

      size += AddFormData(&form, "\r\n\r\n", 0);

      if((post->flags & HTTPPOST_FILENAME) ||
         (post->flags & HTTPPOST_READFILE)) {
        /* we should include the contents from the specified file */
        FILE *fileread;
        char buffer[1024];
        size_t nread;

        fileread = strequal("-", file->contents)?
          stdin:fopen(file->contents, "rb"); /* binary read for win32  */
        /*
         * VMS: This only allows for stream files on VMS.  Stream files are
         * OK, as are FIXED & VAR files WITHOUT implied CC For implied CC,
         * every record needs to have a \n appended & 1 added to SIZE
         */

        if(fileread) {
          while((nread = fread(buffer, 1, 1024, fileread)))
            size += AddFormData(&form, buffer, nread);

          if(fileread != stdin)
            fclose(fileread);
        }
        else {
          Curl_formclean(firstform);
          free(boundary);
          *finalform = NULL;
          return CURLE_READ_ERROR;
        }

      } 
      else if (post->flags & HTTPPOST_BUFFER) {
          /* include contents of buffer */
          size += AddFormData(&form, post->buffer, post->bufferlength);
      }

      else {
        /* include the contents we got */
        size += AddFormData(&form, post->contents, post->contentslength);
      }
    } while((file = file->more)); /* for each specified file for this field */

    if(post->more) {
      /* this was a multiple-file inclusion, make a termination file
         boundary: */
      size += AddFormDataf(&form,
                           "\r\n--%s--",
                           fileboundary);     
      free(fileboundary);
    }

  } while((post=post->next)); /* for each field */

  /* end-boundary for everything */
  size += AddFormDataf(&form,
                       "\r\n--%s--\r\n",
                       boundary);

  *sizep = size;

  free(boundary);

  *finalform=firstform;

  return result;
}

/*
 * Curl_FormInit() inits the struct 'form' points to with the 'formdata'
 * and resets the 'sent' counter.
 */
int Curl_FormInit(struct Form *form, struct FormData *formdata )
{
  if(!formdata)
    return 1; /* error */

  form->data = formdata;
  form->sent = 0;

  return 0;
}

/*
 * Curl_FormReader() is the fread() emulation function that will be used to
 * deliver the formdata to the transfer loop and then sent away to the peer.
 */
size_t Curl_FormReader(char *buffer,
                       size_t size,
                       size_t nitems,
                       FILE *mydata)
{
  struct Form *form;
  size_t wantedsize;
  size_t gotsize = 0;

  form=(struct Form *)mydata;

  wantedsize = size * nitems;

  if(!form->data)
    return 0; /* nothing, error, empty */

  do {
  
    if( (form->data->length - form->sent ) > wantedsize - gotsize) {

      memcpy(buffer + gotsize , form->data->line + form->sent,
             wantedsize - gotsize);

      form->sent += wantedsize-gotsize;

      return wantedsize;
    }

    memcpy(buffer+gotsize,
           form->data->line + form->sent,
           (form->data->length - form->sent) );
    gotsize += form->data->length - form->sent;
    
    form->sent = 0;

    form->data = form->data->next; /* advance */

  } while(form->data);
  /* If we got an empty line and we have more data, we proceed to the next
     line immediately to avoid returning zero before we've reached the end.
     This is the bug reported November 22 1999 on curl 6.3. (Daniel) */

  return gotsize;
}

/*
 * Curl_formpostheader() returns the first line of the formpost, the
 * request-header part (which is not part of the request-body like the rest of
 * the post).
 */
char *Curl_formpostheader(void *formp, size_t *len)
{
  char *header;
  struct Form *form=(struct Form *)formp;

  if(!form->data)
    return 0; /* nothing, ERROR! */

  header = form->data->line;
  *len = form->data->length;

  form->data = form->data->next; /* advance */

  return header;
}


#ifdef _FORM_DEBUG
int FormAddTest(const char * errormsg,
                 struct curl_httppost **httppost,
                 struct curl_httppost **last_post,
                 ...)
{
  int result;
  va_list arg;
  va_start(arg, last_post);
  if ((result = FormAdd(httppost, last_post, arg)))
    fprintf (stderr, "ERROR doing FormAdd ret: %d action: %s\n", result,
             errormsg);
  va_end(arg);
  return result;
}


int main()
{
  char name1[] = "simple_COPYCONTENTS";
  char name2[] = "COPYCONTENTS_+_CONTENTTYPE";
  char name3[] = "PTRNAME_+_NAMELENGTH_+_COPYNAME_+_CONTENTSLENGTH";
  char name4[] = "simple_PTRCONTENTS";
  char name5[] = "PTRCONTENTS_+_CONTENTSLENGTH";
  char name6[] = "PTRCONTENTS_+_CONTENTSLENGTH_+_CONTENTTYPE";
  char name7[] = "FILE1_+_CONTENTTYPE";
  char name8[] = "FILE1_+_FILE2";
  char name9[] = "FILE1_+_FILE2_+_FILE3";
  char name10[] = "ARRAY: FILE1_+_FILE2_+_FILE3";
  char name11[] = "FILECONTENT";
  char value1[] = "value for simple COPYCONTENTS";
  char value2[] = "value for COPYCONTENTS + CONTENTTYPE";
  char value3[] = "value for PTRNAME + NAMELENGTH + COPYNAME + CONTENTSLENGTH";
  char value4[] = "value for simple PTRCONTENTS";
  char value5[] = "value for PTRCONTENTS + CONTENTSLENGTH";
  char value6[] = "value for PTRCOTNENTS + CONTENTSLENGTH + CONTENTTYPE";
  char value7[] = "inet_ntoa_r.h";
  char value8[] = "Makefile.b32.resp";
  char type2[] = "image/gif";
  char type6[] = "text/plain";
  char type7[] = "text/html";
  int name3length = strlen(name3);
  int value3length = strlen(value3);
  int value5length = strlen(value4);
  int value6length = strlen(value5);
  int errors = 0;
  int size;
  size_t nread;
  char buffer[4096];
  struct curl_httppost *httppost=NULL;
  struct curl_httppost *last_post=NULL;
  struct curl_forms forms[4];

  struct FormData *form;
  struct Form formread;

  if (FormAddTest("simple COPYCONTENTS test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name1, CURLFORM_COPYCONTENTS, value1,
                  CURLFORM_END))
    ++errors;
  if (FormAddTest("COPYCONTENTS  + CONTENTTYPE test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name2, CURLFORM_COPYCONTENTS, value2,
                  CURLFORM_CONTENTTYPE, type2, CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  name3[1] = '\0';
  value3[1] = '\0';
  if (FormAddTest("PTRNAME + NAMELENGTH + COPYNAME + CONTENTSLENGTH test",
		  &httppost, &last_post,
                  CURLFORM_PTRNAME, name3, CURLFORM_COPYCONTENTS, value3,
                  CURLFORM_CONTENTSLENGTH, value3length,
		  CURLFORM_NAMELENGTH, name3length, CURLFORM_END))
    ++errors;
  if (FormAddTest("simple PTRCONTENTS test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name4, CURLFORM_PTRCONTENTS, value4,
                  CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  value5[1] = '\0';
  if (FormAddTest("PTRCONTENTS + CONTENTSLENGTH test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name5, CURLFORM_PTRCONTENTS, value5,
                  CURLFORM_CONTENTSLENGTH, value5length, CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  value6[1] = '\0';
  if (FormAddTest("PTRCONTENTS + CONTENTSLENGTH + CONTENTTYPE test",
                  &httppost, &last_post,
                  CURLFORM_COPYNAME, name6, CURLFORM_PTRCONTENTS, value6,
                  CURLFORM_CONTENTSLENGTH, value6length,
                  CURLFORM_CONTENTTYPE, type6, CURLFORM_END))
    ++errors;
  if (FormAddTest("FILE + CONTENTTYPE test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name7, CURLFORM_FILE, value7,
                  CURLFORM_CONTENTTYPE, type7, CURLFORM_END))
    ++errors;
  if (FormAddTest("FILE1 + FILE2 test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name8, CURLFORM_FILE, value7,
                  CURLFORM_FILE, value8, CURLFORM_END))
    ++errors;
  if (FormAddTest("FILE1 + FILE2 + FILE3 test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name9, CURLFORM_FILE, value7,
                  CURLFORM_FILE, value8, CURLFORM_FILE, value7, CURLFORM_END))
    ++errors;
  forms[0].option = CURLFORM_FILE;
  forms[0].value  = value7;
  forms[1].option = CURLFORM_FILE;
  forms[1].value  = value8;
  forms[2].option = CURLFORM_FILE;
  forms[2].value  = value7;
  forms[3].option  = CURLFORM_END;
  if (FormAddTest("FILE1 + FILE2 + FILE3 ARRAY test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name10, CURLFORM_ARRAY, forms,
                  CURLFORM_END))
    ++errors;
  if (FormAddTest("FILECONTENT test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name11, CURLFORM_FILECONTENT, value7,
                  CURLFORM_END))
    ++errors;

  form=Curl_getFormData(httppost, &size);

  Curl_FormInit(&formread, form);

  do {
    nread = Curl_FormReader(buffer, 1, sizeof(buffer),
                            (FILE *)&formread);

    if(-1 == nread)
      break;
    fwrite(buffer, nread, 1, stdout);
  } while(1);

  fprintf(stdout, "size: %d\n", size);
  if (errors)
    fprintf(stdout, "\n==> %d Test(s) failed!\n", errors);
  else
    fprintf(stdout, "\nAll Tests seem to have worked (please check output)\n");

  return 0;
}

#endif

#ifdef _OLD_FORM_DEBUG

int main(int argc, char **argv)
{
#if 0
  char *testargs[]={
    "name1 = data in number one",
    "name2 = number two data",
    "test = @upload"
  };
#endif
  int i;
  char *nextarg;
  struct curl_httppost *httppost=NULL;
  struct curl_httppost *last_post=NULL;
  struct curl_httppost *post;
  int size;
  int nread;
  char buffer[4096];

  struct FormData *form;
  struct Form formread;

  for(i=1; i<argc; i++) {

    if( FormParse( argv[i],
		   &httppost,
		   &last_post)) {
      fprintf(stderr, "Illegally formatted input field: '%s'!\n",
	      argv[i]);
      return 1;
    }
  }

  form=Curl_getFormData(httppost, &size);

  Curl_FormInit(&formread, form);

  do {
    nread = Curl_FormReader(buffer, 1, sizeof(buffer),
                            (FILE *)&formread);

    if(-1 == nread)
      break;
    fwrite(buffer, nread, 1, stderr);
  } while(1);

  fprintf(stderr, "size: %d\n", size);

  return 0;
}

#endif

#endif /* CURL_DISABLE_HTTP */
