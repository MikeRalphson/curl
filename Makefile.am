#
# $Id: Makefile.am,v 1.7 2000-11-17 15:30:01 bagder Exp $
#

AUTOMAKE_OPTIONS = foreign no-dependencies

EXTRA_DIST = curl.spec curl-ssl.spec

SUBDIRS = docs lib src include tests

test:
	@(cd tests; make quiet-test)
