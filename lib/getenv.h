#ifndef __GETENV_H
#define __GETENV_H
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
 *  Contributor(s):
 *   Rafael Sagula <sagula@inf.ufrgs.br>
 *   Sampo Kellomaki <sampo@iki.fi>
 *   Linas Vepstas <linas@linas.org>
 *   Bjorn Reese <breese@imada.ou.dk>
 *   Johan Anderson <johan@homemail.com>
 *   Kjell Ericson <Kjell.Ericson@haxx.se>
 *   Troy Engel <tengel@palladium.net>
 *   Ryan Nelson <ryan@inch.com>
 *   Bjorn Stenberg <Bjorn.Stenberg@haxx.se>
 *   Angus Mackay <amackay@gus.ml.org>
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source: /cvsroot/curl/curl/lib/Attic/getenv.h,v $
 * $Revision: 1.3 $
 * $Date: 2000-06-20 15:31:26 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 * $Log: getenv.h,v $
 * Revision 1.3  2000-06-20 15:31:26  bagder
 * haxx.nu => haxx.se
 *
 * Revision 1.2  2000/01/10 23:36:14  bagder
 * syncing with local edit
 *
 * Revision 1.3  1999/09/06 06:59:40  dast
 * Changed email info
 *
 * Revision 1.2  1999/08/13 07:34:48  dast
 * Changed the URL in the header
 *
 * Revision 1.1.1.1  1999/03/11 22:23:34  dast
 * Imported sources
 *
 ****************************************************************************/

/* Unix and Win32 getenv function call */
char *GetEnv(char *variable);

#endif
