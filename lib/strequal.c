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
 *  Portions created by the Initial Developer are Copyright (C) 2000.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source: /cvsroot/curl/curl/lib/strequal.c,v $
 * $Revision: 1.6 $
 * $Date: 2000-08-24 14:26:33 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include "setup.h"

#include <string.h>

int strequal(const char *first, const char *second)
{
#if defined(HAVE_STRCASECMP)
  return !strcasecmp(first, second);
#elif defined(HAVE_STRCMPI)
  return !strcmpi(first, second);
#elif defined(HAVE_STRICMP)
  return !stricmp(first, second);
#else
  while (*first && *second) {
    if (toupper(*first) != toupper(*second)) {
      break;
    }
    first++;
    second++;
  }
  return toupper(*first) == toupper(*second);
#endif
}

int strnequal(const char *first, const char *second, size_t max)
{
#if defined(HAVE_STRCASECMP)
  return !strncasecmp(first, second, max);
#elif defined(HAVE_STRCMPI)
  return !strncmpi(first, second, max);
#elif defined(HAVE_STRICMP)
  return !strnicmp(first, second, max);
#else
  while (*first && *second && max) {
    if (toupper(*first) != toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  return toupper(*first) == toupper(*second);
#endif
}

