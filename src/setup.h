#ifndef __SETUP_H
#define __SETUP_H
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
 * $Source: /cvsroot/curl/curl/src/setup.h,v $
 * $Revision: 1.5 $
 * $Date: 2000-11-09 12:51:43 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <stdio.h>

#if !defined(WIN32) && defined(_WIN32)
/* This _might_ be a good Borland fix. Please report whether this works or
   not! */
#define WIN32
#endif

#ifdef HAVE_CONFIG_H
#include "config.h" /* the configure script results */
#else
#ifdef WIN32
/* include the hand-modified win32 adjusted config.h! */
#include "config-win32.h"
#endif
#endif

#ifndef OS
#define OS "unknown"
#endif

#ifndef fileno /* sunos 4 have this as a macro! */
int fileno( FILE *stream);
#endif

#ifdef WIN32
#define PATH_CHAR     ";"
#define DIR_CHAR      "\\"
#define DOT_CHAR      "_"
#else
#ifdef __EMX__
/* 20000318 mgs
 * OS/2 supports leading dots in filenames if the volume is formatted
 * with JFS or HPFS. */
#define PATH_CHAR     ";"
#define DIR_CHAR      "\\"
#define DOT_CHAR      "."
#else

#define PATH_CHAR     ":"
#define DIR_CHAR      "/"
#define DOT_CHAR      "."

#endif
#endif

#endif /* __SETUP_H */
