#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# $Id: curl-functions.m4,v 1.10 2008-09-15 15:32:53 yangtse Exp $
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 8


dnl CURL_INCLUDES_SIGNAL
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when signal.h is to be included.

AC_DEFUN([CURL_INCLUDES_SIGNAL], [
curl_includes_signal="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SIGNAL_H
#  include <signal.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h signal.h,
    [], [], [$curl_includes_signal])
])


dnl CURL_INCLUDES_STDIO
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when stdio.h is to be included.

AC_DEFUN([CURL_INCLUDES_STDIO], [
curl_includes_stdio="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h stdio.h,
    [], [], [$curl_includes_stdio])
])


dnl CURL_INCLUDES_STDLIB
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when stdlib.h is to be included.

AC_DEFUN([CURL_INCLUDES_STDLIB], [
curl_includes_stdlib="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h stdlib.h,
    [], [], [$curl_includes_stdlib])
])


dnl CURL_INCLUDES_STRING
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when string(s).h is to be included.

AC_DEFUN([CURL_INCLUDES_STRING], [
curl_includes_string="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h string.h strings.h,
    [], [], [$curl_includes_string])
])


dnl CURL_INCLUDES_TIME
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when time.h is to be included.

AC_DEFUN([CURL_INCLUDES_TIME], [
AC_REQUIRE([AC_HEADER_TIME])dnl
curl_includes_time="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#  ifdef TIME_WITH_SYS_TIME
#    include <time.h>
#  endif
#else
#  ifdef HAVE_TIME_H
#    include <time.h>
#  endif
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/time.h time.h,
    [], [], [$curl_includes_time])
])


dnl CURL_INCLUDES_UNISTD
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when unistd.h is to be included.

AC_DEFUN([CURL_INCLUDES_UNISTD], [
curl_includes_unistd="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h unistd.h,
    [], [], [$curl_includes_unistd])
])


dnl CURL_CHECK_FUNC_FDOPEN
dnl -------------------------------------------------
dnl Verify if fdopen is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_fdopen, then
dnl HAVE_FDOPEN will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FDOPEN], [
  AC_REQUIRE([CURL_INCLUDES_STDIO])dnl
  #
  tst_links_fdopen="unknown"
  tst_proto_fdopen="unknown"
  tst_compi_fdopen="unknown"
  tst_allow_fdopen="unknown"
  #
  AC_MSG_CHECKING([if fdopen can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([fdopen])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_fdopen="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_fdopen="no"
  ])
  #
  if test "$tst_links_fdopen" = "yes"; then
    AC_MSG_CHECKING([if fdopen is prototyped])
    AC_EGREP_CPP([fdopen],[
      $curl_includes_stdio
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_fdopen="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_fdopen="no"
    ])
  fi
  #
  if test "$tst_proto_fdopen" = "yes"; then
    AC_MSG_CHECKING([if fdopen is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdio
      ]],[[
        if(0 != fdopen(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_fdopen="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_fdopen="no"
    ])
  fi
  #
  if test "$tst_compi_fdopen" = "yes"; then
    AC_MSG_CHECKING([if fdopen usage allowed])
    if test "x$curl_disallow_fdopen" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fdopen="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fdopen="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fdopen might be used])
  if test "$tst_links_fdopen" = "yes" &&
     test "$tst_proto_fdopen" = "yes" &&
     test "$tst_compi_fdopen" = "yes" &&
     test "$tst_allow_fdopen" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FDOPEN, 1,
      [Define to 1 if you have the fdopen function.])
    ac_cv_func_fdopen="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_fdopen="no"
  fi
])


dnl CURL_CHECK_FUNC_FTRUNCATE
dnl -------------------------------------------------
dnl Verify if ftruncate is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_ftruncate, then
dnl HAVE_FTRUNCATE will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FTRUNCATE], [
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  #
  tst_links_ftruncate="unknown"
  tst_proto_ftruncate="unknown"
  tst_compi_ftruncate="unknown"
  tst_allow_ftruncate="unknown"
  #
  AC_MSG_CHECKING([if ftruncate can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([ftruncate])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_ftruncate="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_ftruncate="no"
  ])
  #
  if test "$tst_links_ftruncate" = "yes"; then
    AC_MSG_CHECKING([if ftruncate is prototyped])
    AC_EGREP_CPP([ftruncate],[
      $curl_includes_unistd
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_ftruncate="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_ftruncate="no"
    ])
  fi
  #
  if test "$tst_proto_ftruncate" = "yes"; then
    AC_MSG_CHECKING([if ftruncate is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_unistd
      ]],[[
        if(0 != ftruncate(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ftruncate="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ftruncate="no"
    ])
  fi
  #
  if test "$tst_compi_ftruncate" = "yes"; then
    AC_MSG_CHECKING([if ftruncate usage allowed])
    if test "x$curl_disallow_ftruncate" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ftruncate="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ftruncate="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ftruncate might be used])
  if test "$tst_links_ftruncate" = "yes" &&
     test "$tst_proto_ftruncate" = "yes" &&
     test "$tst_compi_ftruncate" = "yes" &&
     test "$tst_allow_ftruncate" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FTRUNCATE, 1,
      [Define to 1 if you have the ftruncate function.])
    ac_cv_func_ftruncate="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_ftruncate="no"
  fi
])


dnl CURL_CHECK_FUNC_GMTIME_R
dnl -------------------------------------------------
dnl Verify if gmtime_r is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_gmtime_r, then
dnl HAVE_GMTIME_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GMTIME_R], [
  AC_REQUIRE([CURL_INCLUDES_TIME])dnl
  #
  tst_links_gmtime_r="unknown"
  tst_proto_gmtime_r="unknown"
  tst_compi_gmtime_r="unknown"
  tst_works_gmtime_r="unknown"
  tst_allow_gmtime_r="unknown"
  #
  AC_MSG_CHECKING([if gmtime_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gmtime_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gmtime_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gmtime_r="no"
  ])
  #
  if test "$tst_links_gmtime_r" = "yes"; then
    AC_MSG_CHECKING([if gmtime_r is prototyped])
    AC_EGREP_CPP([gmtime_r],[
      $curl_includes_time
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gmtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gmtime_r="no"
    ])
  fi
  #
  if test "$tst_proto_gmtime_r" = "yes"; then
    AC_MSG_CHECKING([if gmtime_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_time
      ]],[[
        if(0 != gmtime_r(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gmtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gmtime_r="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_gmtime_r" = "yes"; then
    AC_MSG_CHECKING([if gmtime_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_time
      ]],[[
        time_t local = 1170352587;
        struct tm *gmt = 0;
        struct tm result;
        gmt = gmtime_r(&local, &result);
        if(gmt)
          exit(0);
        else
          exit(1);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_gmtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_gmtime_r="no"
    ])
  fi
  #
  if test "$tst_compi_gmtime_r" = "yes" &&
    test "$tst_works_gmtime_r" != "no"; then
    AC_MSG_CHECKING([if gmtime_r usage allowed])
    if test "x$curl_disallow_gmtime_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gmtime_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gmtime_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gmtime_r might be used])
  if test "$tst_links_gmtime_r" = "yes" &&
     test "$tst_proto_gmtime_r" = "yes" &&
     test "$tst_compi_gmtime_r" = "yes" &&
     test "$tst_allow_gmtime_r" = "yes" &&
     test "$tst_works_gmtime_r" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GMTIME_R, 1,
      [Define to 1 if you have a working gmtime_r function.])
    ac_cv_func_gmtime_r="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_gmtime_r="no"
  fi
])


dnl CURL_CHECK_FUNC_SIGACTION
dnl -------------------------------------------------
dnl Verify if sigaction is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_sigaction, then
dnl HAVE_SIGACTION will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SIGACTION], [
  AC_REQUIRE([CURL_INCLUDES_SIGNAL])dnl
  #
  tst_links_sigaction="unknown"
  tst_proto_sigaction="unknown"
  tst_compi_sigaction="unknown"
  tst_allow_sigaction="unknown"
  #
  AC_MSG_CHECKING([if sigaction can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([sigaction])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_sigaction="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_sigaction="no"
  ])
  #
  if test "$tst_links_sigaction" = "yes"; then
    AC_MSG_CHECKING([if sigaction is prototyped])
    AC_EGREP_CPP([sigaction],[
      $curl_includes_signal
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_sigaction="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_sigaction="no"
    ])
  fi
  #
  if test "$tst_proto_sigaction" = "yes"; then
    AC_MSG_CHECKING([if sigaction is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_signal
      ]],[[
        if(0 != sigaction(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_sigaction="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_sigaction="no"
    ])
  fi
  #
  if test "$tst_compi_sigaction" = "yes"; then
    AC_MSG_CHECKING([if sigaction usage allowed])
    if test "x$curl_disallow_sigaction" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_sigaction="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_sigaction="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if sigaction might be used])
  if test "$tst_links_sigaction" = "yes" &&
     test "$tst_proto_sigaction" = "yes" &&
     test "$tst_compi_sigaction" = "yes" &&
     test "$tst_allow_sigaction" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SIGACTION, 1,
      [Define to 1 if you have the sigaction function.])
    ac_cv_func_sigaction="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_sigaction="no"
  fi
])


dnl CURL_CHECK_FUNC_STRCASECMP
dnl -------------------------------------------------
dnl Verify if strcasecmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strcasecmp, then
dnl HAVE_STRCASECMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRCASECMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strcasecmp="unknown"
  tst_proto_strcasecmp="unknown"
  tst_compi_strcasecmp="unknown"
  tst_allow_strcasecmp="unknown"
  #
  AC_MSG_CHECKING([if strcasecmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strcasecmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strcasecmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strcasecmp="no"
  ])
  #
  if test "$tst_links_strcasecmp" = "yes"; then
    AC_MSG_CHECKING([if strcasecmp is prototyped])
    AC_EGREP_CPP([strcasecmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strcasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strcasecmp="no"
    ])
  fi
  #
  if test "$tst_proto_strcasecmp" = "yes"; then
    AC_MSG_CHECKING([if strcasecmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strcasecmp(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strcasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strcasecmp="no"
    ])
  fi
  #
  if test "$tst_compi_strcasecmp" = "yes"; then
    AC_MSG_CHECKING([if strcasecmp usage allowed])
    if test "x$curl_disallow_strcasecmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strcasecmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strcasecmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strcasecmp might be used])
  if test "$tst_links_strcasecmp" = "yes" &&
     test "$tst_proto_strcasecmp" = "yes" &&
     test "$tst_compi_strcasecmp" = "yes" &&
     test "$tst_allow_strcasecmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRCASECMP, 1,
      [Define to 1 if you have the strcasecmp function.])
    ac_cv_func_strcasecmp="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strcasecmp="no"
  fi
])


dnl CURL_CHECK_FUNC_STRCASESTR
dnl -------------------------------------------------
dnl Verify if strcasestr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strcasestr, then
dnl HAVE_STRCASESTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRCASESTR], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strcasestr="unknown"
  tst_proto_strcasestr="unknown"
  tst_compi_strcasestr="unknown"
  tst_allow_strcasestr="unknown"
  #
  AC_MSG_CHECKING([if strcasestr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strcasestr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strcasestr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strcasestr="no"
  ])
  #
  if test "$tst_links_strcasestr" = "yes"; then
    AC_MSG_CHECKING([if strcasestr is prototyped])
    AC_EGREP_CPP([strcasestr],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strcasestr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strcasestr="no"
    ])
  fi
  #
  if test "$tst_proto_strcasestr" = "yes"; then
    AC_MSG_CHECKING([if strcasestr is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strcasestr(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strcasestr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strcasestr="no"
    ])
  fi
  #
  if test "$tst_compi_strcasestr" = "yes"; then
    AC_MSG_CHECKING([if strcasestr usage allowed])
    if test "x$curl_disallow_strcasestr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strcasestr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strcasestr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strcasestr might be used])
  if test "$tst_links_strcasestr" = "yes" &&
     test "$tst_proto_strcasestr" = "yes" &&
     test "$tst_compi_strcasestr" = "yes" &&
     test "$tst_allow_strcasestr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRCASESTR, 1,
      [Define to 1 if you have the strcasestr function.])
    ac_cv_func_strcasestr="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strcasestr="no"
  fi
])


dnl CURL_CHECK_FUNC_STRCMPI
dnl -------------------------------------------------
dnl Verify if strcmpi is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strcmpi, then
dnl HAVE_STRCMPI will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRCMPI], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strcmpi="unknown"
  tst_proto_strcmpi="unknown"
  tst_compi_strcmpi="unknown"
  tst_allow_strcmpi="unknown"
  #
  AC_MSG_CHECKING([if strcmpi can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strcmpi])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strcmpi="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strcmpi="no"
  ])
  #
  if test "$tst_links_strcmpi" = "yes"; then
    AC_MSG_CHECKING([if strcmpi is prototyped])
    AC_EGREP_CPP([strcmpi],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strcmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strcmpi="no"
    ])
  fi
  #
  if test "$tst_proto_strcmpi" = "yes"; then
    AC_MSG_CHECKING([if strcmpi is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strcmpi(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strcmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strcmpi="no"
    ])
  fi
  #
  if test "$tst_compi_strcmpi" = "yes"; then
    AC_MSG_CHECKING([if strcmpi usage allowed])
    if test "x$curl_disallow_strcmpi" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strcmpi="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strcmpi="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strcmpi might be used])
  if test "$tst_links_strcmpi" = "yes" &&
     test "$tst_proto_strcmpi" = "yes" &&
     test "$tst_compi_strcmpi" = "yes" &&
     test "$tst_allow_strcmpi" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRCMPI, 1,
      [Define to 1 if you have the strcmpi function.])
    ac_cv_func_strcmpi="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strcmpi="no"
  fi
])


dnl CURL_CHECK_FUNC_STRDUP
dnl -------------------------------------------------
dnl Verify if strdup is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strdup, then
dnl HAVE_STRDUP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRDUP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strdup="unknown"
  tst_proto_strdup="unknown"
  tst_compi_strdup="unknown"
  tst_allow_strdup="unknown"
  #
  AC_MSG_CHECKING([if strdup can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strdup])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strdup="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strdup="no"
  ])
  #
  if test "$tst_links_strdup" = "yes"; then
    AC_MSG_CHECKING([if strdup is prototyped])
    AC_EGREP_CPP([strdup],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strdup="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strdup="no"
    ])
  fi
  #
  if test "$tst_proto_strdup" = "yes"; then
    AC_MSG_CHECKING([if strdup is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strdup(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strdup="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strdup="no"
    ])
  fi
  #
  if test "$tst_compi_strdup" = "yes"; then
    AC_MSG_CHECKING([if strdup usage allowed])
    if test "x$curl_disallow_strdup" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strdup="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strdup="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strdup might be used])
  if test "$tst_links_strdup" = "yes" &&
     test "$tst_proto_strdup" = "yes" &&
     test "$tst_compi_strdup" = "yes" &&
     test "$tst_allow_strdup" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRDUP, 1,
      [Define to 1 if you have the strdup function.])
    ac_cv_func_strdup="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strdup="no"
  fi
])


dnl CURL_CHECK_FUNC_STRERROR_R
dnl -------------------------------------------------
dnl Verify if strerror_r is available, prototyped, can be compiled and
dnl seems to work. If all of these are true, and usage has not been
dnl previously disallowed with shell variable curl_disallow_strerror_r,
dnl then HAVE_STRERROR_R and STRERROR_R_TYPE_ARG3 will be defined, as
dnl well as one of HAVE_GLIBC_STRERROR_R or HAVE_POSIX_STRERROR_R.
dnl
dnl glibc-style strerror_r:
dnl
dnl      char *strerror_r(int errnum, char *workbuf, size_t bufsize);
dnl
dnl  glibc-style strerror_r returns a pointer to the the error string,
dnl  and might use the provided workbuf as a scratch area if needed. A
dnl  quick test on a few systems shows that it's usually not used at all.
dnl
dnl POSIX-style strerror_r:
dnl
dnl      int strerror_r(int errnum, char *resultbuf, size_t bufsize);
dnl
dnl  POSIX-style strerror_r returns 0 upon successful completion and the
dnl  error string in the provided resultbuf.
dnl

AC_DEFUN([CURL_CHECK_FUNC_STRERROR_R], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strerror_r="unknown"
  tst_proto_strerror_r="unknown"
  tst_compi_strerror_r="unknown"
  tst_glibc_strerror_r="unknown"
  tst_posix_strerror_r="unknown"
  tst_allow_strerror_r="unknown"
  tst_works_glibc_strerror_r="unknown"
  tst_works_posix_strerror_r="unknown"
  tst_glibc_strerror_r_type_arg3="unknown"
  tst_posix_strerror_r_type_arg3="unknown"
  #
  AC_MSG_CHECKING([if strerror_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strerror_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strerror_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strerror_r="no"
  ])
  #
  if test "$tst_links_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r is prototyped])
    AC_EGREP_CPP([strerror_r],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strerror_r="no"
    ])
  fi
  #
  if test "$tst_proto_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strerror_r(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strerror_r="no"
    ])
  fi
  #
  if test "$tst_compi_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r is glibc like])
    tst_glibc_strerror_r_type_arg3="unknown"
    for arg3 in 'size_t' 'int' 'unsigned int'; do
      if test "$tst_glibc_strerror_r_type_arg3" = "unknown"; then
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
            $curl_includes_string
          ]],[[
            char *strerror_r(int errnum, char *workbuf, $arg3 bufsize);
            if(0 != strerror_r(0, 0, 0))
              return 1;
          ]])
        ],[
          tst_glibc_strerror_r_type_arg3="$arg3"
        ])
      fi
    done
    case "$tst_glibc_strerror_r_type_arg3" in
      unknown)
        AC_MSG_RESULT([no])
        tst_glibc_strerror_r="no"
        ;;
      *)
        AC_MSG_RESULT([yes])
        tst_glibc_strerror_r="yes"
        ;;
    esac
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_glibc_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
#       include <errno.h>
      ]],[[
        char buffer[1024];
        char *string = 0;
        buffer[0] = '\0';
        string = strerror_r(EACCES, buffer, sizeof(buffer));
        if(!string)
          exit(1); /* fail */
        if(!string[0])
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_glibc_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_glibc_strerror_r="no"
    ])
  fi
  #
  if test "$tst_compi_strerror_r" = "yes" &&
    test "$tst_works_glibc_strerror_r" != "yes"; then
    AC_MSG_CHECKING([if strerror_r is POSIX like])
    tst_posix_strerror_r_type_arg3="unknown"
    for arg3 in 'size_t' 'int' 'unsigned int'; do
      if test "$tst_posix_strerror_r_type_arg3" = "unknown"; then
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
            $curl_includes_string
          ]],[[
            int strerror_r(int errnum, char *resultbuf, $arg3 bufsize);
            if(0 != strerror_r(0, 0, 0))
              return 1;
          ]])
        ],[
          tst_posix_strerror_r_type_arg3="$arg3"
        ])
      fi
    done
    case "$tst_posix_strerror_r_type_arg3" in
      unknown)
        AC_MSG_RESULT([no])
        tst_posix_strerror_r="no"
        ;;
      *)
        AC_MSG_RESULT([yes])
        tst_posix_strerror_r="yes"
        ;;
    esac
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_posix_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
#       include <errno.h>
      ]],[[
        char buffer[1024];
        int error = 1;
        buffer[0] = '\0';
        error = strerror_r(EACCES, buffer, sizeof(buffer));
        if(error)
          exit(1); /* fail */
        if(buffer[0] == '\0')
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_posix_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_posix_strerror_r="no"
    ])
  fi
  #
  if test "$tst_glibc_strerror_r" = "yes" &&
    test "$tst_works_glibc_strerror_r" != "no" &&
    test "$tst_posix_strerror_r" != "yes"; then
    tst_allow_strerror_r="check"
  fi
  if test "$tst_posix_strerror_r" = "yes" &&
    test "$tst_works_posix_strerror_r" != "no" &&
    test "$tst_glibc_strerror_r" != "yes"; then
    tst_allow_strerror_r="check"
  fi
  if test "$tst_allow_strerror_r" = "check"; then
    AC_MSG_CHECKING([if strerror_r usage allowed])
    if test "x$curl_disallow_strerror_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strerror_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strerror_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strerror_r might be used])
  if test "$tst_links_strerror_r" = "yes" &&
     test "$tst_proto_strerror_r" = "yes" &&
     test "$tst_compi_strerror_r" = "yes" &&
     test "$tst_allow_strerror_r" = "yes"; then
    AC_MSG_RESULT([yes])
    if test "$tst_glibc_strerror_r" = "yes"; then
      AC_DEFINE_UNQUOTED(HAVE_STRERROR_R, 1,
        [Define to 1 if you have the strerror_r function.])
      AC_DEFINE_UNQUOTED(HAVE_GLIBC_STRERROR_R, 1,
        [Define to 1 if you have a working glibc-style strerror_r function.])
      AC_DEFINE_UNQUOTED(STRERROR_R_TYPE_ARG3, $tst_glibc_strerror_r_type_arg3,
        [Define to the type of arg 3 for strerror_r.])
    fi
    if test "$tst_posix_strerror_r" = "yes"; then
      AC_DEFINE_UNQUOTED(HAVE_STRERROR_R, 1,
        [Define to 1 if you have the strerror_r function.])
      AC_DEFINE_UNQUOTED(HAVE_POSIX_STRERROR_R, 1,
        [Define to 1 if you have a working POSIX-style strerror_r function.])
      AC_DEFINE_UNQUOTED(STRERROR_R_TYPE_ARG3, $tst_posix_strerror_r_type_arg3,
        [Define to the type of arg 3 for strerror_r.])
    fi
    ac_cv_func_strerror_r="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strerror_r="no"
  fi
  #
  if test "$tst_compi_strerror_r" = "yes" &&
     test "$tst_allow_strerror_r" = "unknown"; then
    AC_MSG_NOTICE([cannot determine strerror_r() style: edit lib/config.h manually.])
  fi
  #
])


dnl CURL_CHECK_FUNC_STRICMP
dnl -------------------------------------------------
dnl Verify if stricmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_stricmp, then
dnl HAVE_STRICMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRICMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_stricmp="unknown"
  tst_proto_stricmp="unknown"
  tst_compi_stricmp="unknown"
  tst_allow_stricmp="unknown"
  #
  AC_MSG_CHECKING([if stricmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([stricmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_stricmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_stricmp="no"
  ])
  #
  if test "$tst_links_stricmp" = "yes"; then
    AC_MSG_CHECKING([if stricmp is prototyped])
    AC_EGREP_CPP([stricmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_stricmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_stricmp="no"
    ])
  fi
  #
  if test "$tst_proto_stricmp" = "yes"; then
    AC_MSG_CHECKING([if stricmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != stricmp(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_stricmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_stricmp="no"
    ])
  fi
  #
  if test "$tst_compi_stricmp" = "yes"; then
    AC_MSG_CHECKING([if stricmp usage allowed])
    if test "x$curl_disallow_stricmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_stricmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_stricmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if stricmp might be used])
  if test "$tst_links_stricmp" = "yes" &&
     test "$tst_proto_stricmp" = "yes" &&
     test "$tst_compi_stricmp" = "yes" &&
     test "$tst_allow_stricmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRICMP, 1,
      [Define to 1 if you have the stricmp function.])
    ac_cv_func_stricmp="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_stricmp="no"
  fi
])


dnl CURL_CHECK_FUNC_STRLCAT
dnl -------------------------------------------------
dnl Verify if strlcat is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strlcat, then
dnl HAVE_STRLCAT will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRLCAT], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strlcat="unknown"
  tst_proto_strlcat="unknown"
  tst_compi_strlcat="unknown"
  tst_allow_strlcat="unknown"
  #
  AC_MSG_CHECKING([if strlcat can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strlcat])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strlcat="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strlcat="no"
  ])
  #
  if test "$tst_links_strlcat" = "yes"; then
    AC_MSG_CHECKING([if strlcat is prototyped])
    AC_EGREP_CPP([strlcat],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strlcat="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strlcat="no"
    ])
  fi
  #
  if test "$tst_proto_strlcat" = "yes"; then
    AC_MSG_CHECKING([if strlcat is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strlcat(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strlcat="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strlcat="no"
    ])
  fi
  #
  if test "$tst_compi_strlcat" = "yes"; then
    AC_MSG_CHECKING([if strlcat usage allowed])
    if test "x$curl_disallow_strlcat" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strlcat="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strlcat="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strlcat might be used])
  if test "$tst_links_strlcat" = "yes" &&
     test "$tst_proto_strlcat" = "yes" &&
     test "$tst_compi_strlcat" = "yes" &&
     test "$tst_allow_strlcat" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRLCAT, 1,
      [Define to 1 if you have the strlcat function.])
    ac_cv_func_strlcat="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strlcat="no"
  fi
])


dnl CURL_CHECK_FUNC_STRNCASECMP
dnl -------------------------------------------------
dnl Verify if strncasecmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strncasecmp, then
dnl HAVE_STRNCASECMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRNCASECMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strncasecmp="unknown"
  tst_proto_strncasecmp="unknown"
  tst_compi_strncasecmp="unknown"
  tst_allow_strncasecmp="unknown"
  #
  AC_MSG_CHECKING([if strncasecmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strncasecmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strncasecmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strncasecmp="no"
  ])
  #
  if test "$tst_links_strncasecmp" = "yes"; then
    AC_MSG_CHECKING([if strncasecmp is prototyped])
    AC_EGREP_CPP([strncasecmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strncasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strncasecmp="no"
    ])
  fi
  #
  if test "$tst_proto_strncasecmp" = "yes"; then
    AC_MSG_CHECKING([if strncasecmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strncasecmp(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strncasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strncasecmp="no"
    ])
  fi
  #
  if test "$tst_compi_strncasecmp" = "yes"; then
    AC_MSG_CHECKING([if strncasecmp usage allowed])
    if test "x$curl_disallow_strncasecmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strncasecmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strncasecmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strncasecmp might be used])
  if test "$tst_links_strncasecmp" = "yes" &&
     test "$tst_proto_strncasecmp" = "yes" &&
     test "$tst_compi_strncasecmp" = "yes" &&
     test "$tst_allow_strncasecmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRNCASECMP, 1,
      [Define to 1 if you have the strncasecmp function.])
    ac_cv_func_strncasecmp="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strncasecmp="no"
  fi
])


dnl CURL_CHECK_FUNC_STRNCMPI
dnl -------------------------------------------------
dnl Verify if strncmpi is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strncmpi, then
dnl HAVE_STRNCMPI will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRNCMPI], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strncmpi="unknown"
  tst_proto_strncmpi="unknown"
  tst_compi_strncmpi="unknown"
  tst_allow_strncmpi="unknown"
  #
  AC_MSG_CHECKING([if strncmpi can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strncmpi])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strncmpi="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strncmpi="no"
  ])
  #
  if test "$tst_links_strncmpi" = "yes"; then
    AC_MSG_CHECKING([if strncmpi is prototyped])
    AC_EGREP_CPP([strncmpi],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strncmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strncmpi="no"
    ])
  fi
  #
  if test "$tst_proto_strncmpi" = "yes"; then
    AC_MSG_CHECKING([if strncmpi is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strncmpi(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strncmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strncmpi="no"
    ])
  fi
  #
  if test "$tst_compi_strncmpi" = "yes"; then
    AC_MSG_CHECKING([if strncmpi usage allowed])
    if test "x$curl_disallow_strncmpi" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strncmpi="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strncmpi="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strncmpi might be used])
  if test "$tst_links_strncmpi" = "yes" &&
     test "$tst_proto_strncmpi" = "yes" &&
     test "$tst_compi_strncmpi" = "yes" &&
     test "$tst_allow_strncmpi" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRNCMPI, 1,
      [Define to 1 if you have the strncmpi function.])
    ac_cv_func_strncmpi="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strncmpi="no"
  fi
])


dnl CURL_CHECK_FUNC_STRNICMP
dnl -------------------------------------------------
dnl Verify if strnicmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strnicmp, then
dnl HAVE_STRNICMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRNICMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strnicmp="unknown"
  tst_proto_strnicmp="unknown"
  tst_compi_strnicmp="unknown"
  tst_allow_strnicmp="unknown"
  #
  AC_MSG_CHECKING([if strnicmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strnicmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strnicmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strnicmp="no"
  ])
  #
  if test "$tst_links_strnicmp" = "yes"; then
    AC_MSG_CHECKING([if strnicmp is prototyped])
    AC_EGREP_CPP([strnicmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strnicmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strnicmp="no"
    ])
  fi
  #
  if test "$tst_proto_strnicmp" = "yes"; then
    AC_MSG_CHECKING([if strnicmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strnicmp(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strnicmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strnicmp="no"
    ])
  fi
  #
  if test "$tst_compi_strnicmp" = "yes"; then
    AC_MSG_CHECKING([if strnicmp usage allowed])
    if test "x$curl_disallow_strnicmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strnicmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strnicmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strnicmp might be used])
  if test "$tst_links_strnicmp" = "yes" &&
     test "$tst_proto_strnicmp" = "yes" &&
     test "$tst_compi_strnicmp" = "yes" &&
     test "$tst_allow_strnicmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRNICMP, 1,
      [Define to 1 if you have the strnicmp function.])
    ac_cv_func_strnicmp="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strnicmp="no"
  fi
])


dnl CURL_CHECK_FUNC_STRTOK_R
dnl -------------------------------------------------
dnl Verify if strtok_r is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strtok_r, then
dnl HAVE_STRTOK_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRTOK_R], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strtok_r="unknown"
  tst_proto_strtok_r="unknown"
  tst_compi_strtok_r="unknown"
  tst_allow_strtok_r="unknown"
  #
  AC_MSG_CHECKING([if strtok_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strtok_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strtok_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strtok_r="no"
  ])
  #
  if test "$tst_links_strtok_r" = "yes"; then
    AC_MSG_CHECKING([if strtok_r is prototyped])
    AC_EGREP_CPP([strtok_r],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strtok_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strtok_r="no"
    ])
  fi
  #
  if test "$tst_proto_strtok_r" = "yes"; then
    AC_MSG_CHECKING([if strtok_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strtok_r(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strtok_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strtok_r="no"
    ])
  fi
  #
  if test "$tst_compi_strtok_r" = "yes"; then
    AC_MSG_CHECKING([if strtok_r usage allowed])
    if test "x$curl_disallow_strtok_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strtok_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strtok_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strtok_r might be used])
  if test "$tst_links_strtok_r" = "yes" &&
     test "$tst_proto_strtok_r" = "yes" &&
     test "$tst_compi_strtok_r" = "yes" &&
     test "$tst_allow_strtok_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRTOK_R, 1,
      [Define to 1 if you have the strtok_r function.])
    ac_cv_func_strtok_r="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strtok_r="no"
  fi
])


dnl CURL_CHECK_FUNC_STRTOLL
dnl -------------------------------------------------
dnl Verify if strtoll is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strtoll, then
dnl HAVE_STRTOLL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRTOLL], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  #
  tst_links_strtoll="unknown"
  tst_proto_strtoll="unknown"
  tst_compi_strtoll="unknown"
  tst_allow_strtoll="unknown"
  #
  AC_MSG_CHECKING([if strtoll can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strtoll])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strtoll="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strtoll="no"
  ])
  #
  if test "$tst_links_strtoll" = "yes"; then
    AC_MSG_CHECKING([if strtoll is prototyped])
    AC_EGREP_CPP([strtoll],[
      $curl_includes_stdlib
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strtoll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strtoll="no"
    ])
  fi
  #
  if test "$tst_proto_strtoll" = "yes"; then
    AC_MSG_CHECKING([if strtoll is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
      ]],[[
        if(0 != strtoll(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strtoll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strtoll="no"
    ])
  fi
  #
  if test "$tst_compi_strtoll" = "yes"; then
    AC_MSG_CHECKING([if strtoll usage allowed])
    if test "x$curl_disallow_strtoll" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strtoll="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strtoll="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strtoll might be used])
  if test "$tst_links_strtoll" = "yes" &&
     test "$tst_proto_strtoll" = "yes" &&
     test "$tst_compi_strtoll" = "yes" &&
     test "$tst_allow_strtoll" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRTOLL, 1,
      [Define to 1 if you have the strtoll function.])
    ac_cv_func_strtoll="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strtoll="no"
  fi
])


