#
# $Id: Makefile.am,v 1.1 2002-12-12 12:11:16 bagder Exp $
#

AUTOMAKE_OPTIONS = foreign nostdinc

INCLUDES = -I$(top_srcdir)/include

LIBDIR = ../../lib

# here are all tools used for running libcurl tests
bin_PROGRAMS = lib500 lib501

lib500_SOURCES = lib500.c
lib500_LDADD = $(LIBDIR)/libcurl.la
lib500_DEPENDENCIES = $(LIBDIR)/libcurl.la

lib501_SOURCES = lib501.c
lib501_LDADD = $(LIBDIR)/libcurl.la
lib501_DEPENDENCIES = $(LIBDIR)/libcurl.la
