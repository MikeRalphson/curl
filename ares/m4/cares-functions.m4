#***************************************************************************
# $Id: cares-functions.m4,v 1.6 2008-09-18 02:23:33 yangtse Exp $
#
# Copyright (C) 2008 by Daniel Stenberg et al
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted, provided
# that the above copyright notice appear in all copies and that both that
# copyright notice and this permission notice appear in supporting
# documentation, and that the name of M.I.T. not be used in advertising or
# publicity pertaining to distribution of the software without specific,
# written prior permission.  M.I.T. makes no representations about the
# suitability of this software for any purpose.  It is provided "as is"
# without express or implied warranty.
#
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 5


dnl CARES_INCLUDES_NETDB
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when netdb.h is to be included.

AC_DEFUN([CARES_INCLUDES_NETDB], [
cares_includes_netdb="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h netdb.h,
    [], [], [$cares_includes_netdb])
])


dnl CARES_INCLUDES_STRING
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when string(s).h is to be included.

AC_DEFUN([CARES_INCLUDES_STRING], [
cares_includes_string="\
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
    [], [], [$cares_includes_string])
])


dnl CARES_INCLUDES_SYS_UIO
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when sys/uio.h is to be included.

AC_DEFUN([CARES_INCLUDES_SYS_UIO], [
cares_includes_sys_uio="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/uio.h,
    [], [], [$cares_includes_sys_uio])
])


dnl CARES_INCLUDES_UNISTD
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when unistd.h is to be included.

AC_DEFUN([CARES_INCLUDES_UNISTD], [
cares_includes_unistd="\
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
    [], [], [$cares_includes_unistd])
])


dnl CARES_CHECK_FUNC_GETHOSTNAME
dnl -------------------------------------------------
dnl Verify if gethostname is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_gethostname, then
dnl HAVE_GETHOSTNAME will be defined.

AC_DEFUN([CARES_CHECK_FUNC_GETHOSTNAME], [
  AC_REQUIRE([CARES_INCLUDES_UNISTD])dnl
  #
  tst_links_gethostname="unknown"
  tst_proto_gethostname="unknown"
  tst_compi_gethostname="unknown"
  tst_allow_gethostname="unknown"
  #
  AC_MSG_CHECKING([if gethostname can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostname])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gethostname="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gethostname="no"
  ])
  #
  if test "$tst_links_gethostname" = "yes"; then
    AC_MSG_CHECKING([if gethostname is prototyped])
    AC_EGREP_CPP([gethostname],[
      $cares_includes_unistd
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gethostname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gethostname="no"
    ])
  fi
  #
  if test "$tst_proto_gethostname" = "yes"; then
    AC_MSG_CHECKING([if gethostname is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $cares_includes_unistd
      ]],[[
        if(0 != gethostname(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gethostname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gethostname="no"
    ])
  fi
  #
  if test "$tst_compi_gethostname" = "yes"; then
    AC_MSG_CHECKING([if gethostname usage allowed])
    if test "x$cares_disallow_gethostname" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gethostname="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gethostname="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gethostname might be used])
  if test "$tst_links_gethostname" = "yes" &&
     test "$tst_proto_gethostname" = "yes" &&
     test "$tst_compi_gethostname" = "yes" &&
     test "$tst_allow_gethostname" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETHOSTNAME, 1,
      [Define to 1 if you have the gethostname function.])
    ac_cv_func_gethostname="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_gethostname="no"
  fi
])


dnl CARES_CHECK_FUNC_GETSERVBYPORT_R
dnl -------------------------------------------------
dnl Verify if getservbyport_r is available, prototyped,
dnl and can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_getservbyport_r, then
dnl HAVE_GETSERVBYPORT_R will be defined.

AC_DEFUN([CARES_CHECK_FUNC_GETSERVBYPORT_R], [
  AC_REQUIRE([CARES_INCLUDES_NETDB])dnl
  #
  tst_links_getservbyport_r="unknown"
  tst_proto_getservbyport_r="unknown"
  tst_compi_getservbyport_r="unknown"
  tst_allow_getservbyport_r="unknown"
  tst_nargs_getservbyport_r="unknown"
  #
  AC_MSG_CHECKING([if getservbyport_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getservbyport_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getservbyport_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getservbyport_r="no"
  ])
  #
  if test "$tst_links_getservbyport_r" = "yes"; then
    AC_MSG_CHECKING([if getservbyport_r is prototyped])
    AC_EGREP_CPP([getservbyport_r],[
      $cares_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getservbyport_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getservbyport_r="no"
    ])
  fi
  #
  if test "$tst_proto_getservbyport_r" = "yes"; then
    if test "$tst_nargs_getservbyport_r" = "unknown"; then
      AC_MSG_CHECKING([if getservbyport_r takes 4 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $cares_includes_netdb
        ]],[[
          if(0 != getservbyport_r(0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getservbyport_r="yes"
        tst_nargs_getservbyport_r="4"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getservbyport_r="no"
      ])
    fi
    if test "$tst_nargs_getservbyport_r" = "unknown"; then
      AC_MSG_CHECKING([if getservbyport_r takes 5 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $cares_includes_netdb
        ]],[[
          if(0 != getservbyport_r(0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getservbyport_r="yes"
        tst_nargs_getservbyport_r="5"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getservbyport_r="no"
      ])
    fi
    if test "$tst_nargs_getservbyport_r" = "unknown"; then
      AC_MSG_CHECKING([if getservbyport_r takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $cares_includes_netdb
        ]],[[
          if(0 != getservbyport_r(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getservbyport_r="yes"
        tst_nargs_getservbyport_r="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getservbyport_r="no"
      ])
    fi
    AC_MSG_CHECKING([if getservbyport_r is compilable])
    if test "$tst_compi_getservbyport_r" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_getservbyport_r" = "yes"; then
    AC_MSG_CHECKING([if getservbyport_r usage allowed])
    if test "x$cares_disallow_getservbyport_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getservbyport_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getservbyport_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getservbyport_r might be used])
  if test "$tst_links_getservbyport_r" = "yes" &&
     test "$tst_proto_getservbyport_r" = "yes" &&
     test "$tst_compi_getservbyport_r" = "yes" &&
     test "$tst_allow_getservbyport_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETSERVBYPORT_R, 1,
      [Define to 1 if you have the getservbyport_r function.])
    AC_DEFINE_UNQUOTED(GETSERVBYPORT_R_ARGS, $tst_nargs_getservbyport_r,
      [Specifies the number of arguments to getservbyport_r])
    if test "$tst_nargs_getservbyport_r" -eq "4"; then
      AC_DEFINE(GETSERVBYPORT_R_BUFSIZE, sizeof(struct servent_data),
        [Specifies the size of the buffer to pass to getservbyport_r])
    else
      AC_DEFINE(GETSERVBYPORT_R_BUFSIZE, 4096,
        [Specifies the size of the buffer to pass to getservbyport_r])
    fi
    ac_cv_func_getservbyport_r="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_getservbyport_r="no"
  fi
])


dnl CARES_CHECK_FUNC_STRCASECMP
dnl -------------------------------------------------
dnl Verify if strcasecmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strcasecmp, then
dnl HAVE_STRCASECMP will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRCASECMP], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_strcasecmp" != "xyes"; then
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


dnl CARES_CHECK_FUNC_STRCMPI
dnl -------------------------------------------------
dnl Verify if strcmpi is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strcmpi, then
dnl HAVE_STRCMPI will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRCMPI], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_strcmpi" != "xyes"; then
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


dnl CARES_CHECK_FUNC_STRDUP
dnl -------------------------------------------------
dnl Verify if strdup is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strdup, then
dnl HAVE_STRDUP will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRDUP], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_strdup" != "xyes"; then
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


dnl CARES_CHECK_FUNC_STRICMP
dnl -------------------------------------------------
dnl Verify if stricmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_stricmp, then
dnl HAVE_STRICMP will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRICMP], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_stricmp" != "xyes"; then
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


dnl CARES_CHECK_FUNC_STRNCASECMP
dnl -------------------------------------------------
dnl Verify if strncasecmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strncasecmp, then
dnl HAVE_STRNCASECMP will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRNCASECMP], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_strncasecmp" != "xyes"; then
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


dnl CARES_CHECK_FUNC_STRNCMPI
dnl -------------------------------------------------
dnl Verify if strncmpi is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strncmpi, then
dnl HAVE_STRNCMPI will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRNCMPI], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_strncmpi" != "xyes"; then
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


dnl CARES_CHECK_FUNC_STRNICMP
dnl -------------------------------------------------
dnl Verify if strnicmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strnicmp, then
dnl HAVE_STRNICMP will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRNICMP], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
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
    if test "x$cares_disallow_strnicmp" != "xyes"; then
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


dnl CARES_CHECK_FUNC_WRITEV
dnl -------------------------------------------------
dnl Verify if writev is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_writev, then
dnl HAVE_WRITEV will be defined.

AC_DEFUN([CARES_CHECK_FUNC_WRITEV], [
  AC_REQUIRE([CARES_INCLUDES_SYS_UIO])dnl
  #
  tst_links_writev="unknown"
  tst_proto_writev="unknown"
  tst_compi_writev="unknown"
  tst_allow_writev="unknown"
  #
  AC_MSG_CHECKING([if writev can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([writev])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_writev="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_writev="no"
  ])
  #
  if test "$tst_links_writev" = "yes"; then
    AC_MSG_CHECKING([if writev is prototyped])
    AC_EGREP_CPP([writev],[
      $cares_includes_sys_uio
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_writev="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_writev="no"
    ])
  fi
  #
  if test "$tst_proto_writev" = "yes"; then
    AC_MSG_CHECKING([if writev is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $cares_includes_sys_uio
      ]],[[
        if(0 != writev(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_writev="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_writev="no"
    ])
  fi
  #
  if test "$tst_compi_writev" = "yes"; then
    AC_MSG_CHECKING([if writev usage allowed])
    if test "x$cares_disallow_writev" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_writev="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_writev="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if writev might be used])
  if test "$tst_links_writev" = "yes" &&
     test "$tst_proto_writev" = "yes" &&
     test "$tst_compi_writev" = "yes" &&
     test "$tst_allow_writev" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_WRITEV, 1,
      [Define to 1 if you have the writev function.])
    ac_cv_func_writev="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_writev="no"
  fi
])
