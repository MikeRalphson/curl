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
# $Id: curl-functions.m4,v 1.1 2008-09-10 17:33:15 yangtse Exp $
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 1


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
        gmtime_r(0, 0);
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
  if test "$tst_works_gmtime_r" != "no"; then
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
        strtoll(0, 0, 0);
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


