@echo off
REM set up a CVS tree to build when there's no autotools
REM $Revision: 1.1 $
REM $Date: 2004-02-26 16:13:13 $

REM create ca-bundle.h
echo /* This file is generated automatically */ >lib\ca-bundle.h
echo #define CURL_CA_BUNDLE getenv("CURL_CA_BUNDLE") >>lib\ca-bundle.h

REM create getdate.c
copy lib\getdate.c.cvs lib\getdate.c

REM create hugehelp.c
copy src\hugehelp.c.cvs src\hugehelp.c

REM create Makefile
copy Makefile.dist Makefile