#ifndef __PROGRESS_H
#define __PROGRESS_H
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
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source: /cvsroot/curl/curl/lib/progress.h,v $
 * $Revision: 1.1.1.1 $
 * $Date: 1999-12-29 14:21:35 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include "timeval.h"

void ProgressInit(struct UrlData *data, int max);
void ProgressShow(struct UrlData *data,
                  int point, struct timeval start, struct timeval now, bool force);
void ProgressEnd(struct UrlData *data);
void ProgressMode(int mode);

/* Don't show progress for sizes smaller than: */
#define LEAST_SIZE_PROGRESS BUFSIZE

#endif /* __PROGRESS_H */
