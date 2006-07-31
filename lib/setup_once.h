#ifndef __SETUP_ONCE_H
#define __SETUP_ONCE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id: setup_once.h,v 1.2 2006-07-31 17:12:24 yangtse Exp $
 ***************************************************************************/


/*
 * If we have the MSG_NOSIGNAL define, make sure we use
 * it as the fourth argument of send() and recv()
 */

#ifdef HAVE_MSG_NOSIGNAL
#define SEND_4TH_ARG MSG_NOSIGNAL
#else
#define SEND_4TH_ARG 0
#endif 


/*
 * The definitions for the return type and arguments types
 * of functions recv() and send() belong and come from the
 * configuration file. Do not define them in any other place.
 *
 * HAVE_RECV is defined if you have a function named recv()
 * which is used to read incoming data from sockets. If your
 * function has another name then don't define HAVE_RECV.
 *
 * If HAVE_RECV is defined then RECV_TYPE_ARG1, RECV_TYPE_ARG2,
 * RECV_TYPE_ARG3, RECV_TYPE_ARG4 and RECV_TYPE_RETV must also
 * be defined.
 *
 * HAVE_SEND is defined if you have a function named send()
 * which is used to write outgoing data on a connected socket.
 * If yours has another name then don't define HAVE_SEND.
 *
 * If HAVE_SEND is defined then SEND_TYPE_ARG1, SEND_QUAL_ARG2,
 * SEND_TYPE_ARG2, SEND_TYPE_ARG3, SEND_TYPE_ARG4 and
 * SEND_TYPE_RETV must also be defined.
 */

#ifdef HAVE_RECV
#if !defined(RECV_TYPE_ARG1) || \
    !defined(RECV_TYPE_ARG2) || \
    !defined(RECV_TYPE_ARG3) || \
    !defined(RECV_TYPE_ARG4) || \
    !defined(RECV_TYPE_RETV)
  /* */
  Error Missing_definition_of_return_and_arguments_types_of_recv
  /* */
#else
#define sread(x,y,z) (ssize_t)recv((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z), \
                                   (RECV_TYPE_ARG4)(SEND_4TH_ARG))
#endif
#else /* HAVE_RECV */
#ifdef DJGPP
#define sread(x,y,z) (ssize_t)read_s((int)(x), (char *)(y), (int)(z))
#endif
#ifndef sread
  /* */
  Error Missing_definition_of_macro_sread
  /* */
#endif
#endif /* HAVE_RECV */

#ifdef HAVE_SEND
#if !defined(SEND_TYPE_ARG1) || \
    !defined(SEND_QUAL_ARG2) || \
    !defined(SEND_TYPE_ARG2) || \
    !defined(SEND_TYPE_ARG3) || \
    !defined(SEND_TYPE_ARG4) || \
    !defined(SEND_TYPE_RETV)
  /* */
  Error Missing_definition_of_return_and_arguments_types_of_send
  /* */
#else
#define swrite(x,y,z) (ssize_t)send((SEND_TYPE_ARG1)(x), \
                                    (SEND_TYPE_ARG2)(y), \
                                    (SEND_TYPE_ARG3)(z), \
                                    (SEND_TYPE_ARG4)(SEND_4TH_ARG))
#endif
#else /* HAVE_SEND */
#ifdef DJGPP
#define swrite(x,y,z) (ssize_t)write_s((int)(x), (char *)(y), (int)(z))
#endif
#ifndef swrite
  /* */
  Error Missing_definition_of_macro_swrite
  /* */
#endif
#endif /* HAVE_SEND */


#endif /* __SETUP_ONCE_H */

