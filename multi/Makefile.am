#
# $Id: Makefile.am,v 1.1.2.1 2001-12-18 01:02:20 bagder Exp $
#

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = app

app_SOURCES = app.c
app_LDADD = ../lib/libcurl.la
app_DEPENDENCIES = ../lib/libcurl.la
AUTOMAKE_OPTIONS = foreign no-dependencies
