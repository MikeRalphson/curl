#
# $Id: Makefile.am,v 1.6 2000-11-10 14:42:06 bagder Exp $
#

AUTOMAKE_OPTIONS = foreign no-dependencies

EXTRA_DIST = curl.spec curl-ssl.spec

SUBDIRS = docs lib src include tests

test:
	@(cd tests; make test)
