#
# $Id: Makefile.am,v 1.1.2.3 2001-12-18 14:51:53 bagder Exp $
#

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = app single double

app_SOURCES = app.c
app_LDADD = ../lib/libcurl.la
app_DEPENDENCIES = ../lib/libcurl.la

single_SOURCES = single.c
single_LDADD = ../lib/libcurl.la
single_DEPENDENCIES = ../lib/libcurl.la

double_SOURCES = double.c
double_LDADD = ../lib/libcurl.la
double_DEPENDENCIES = ../lib/libcurl.la

AUTOMAKE_OPTIONS = foreign no-dependencies
