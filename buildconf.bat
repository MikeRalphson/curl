@echo off
REM set up a CVS tree to build when there's no autotools
REM $Revision: 1.7 $
REM $Date: 2009-04-30 10:43:27 $

REM create hugehelp.c
copy src\hugehelp.c.cvs src\hugehelp.c

REM create Makefile
copy Makefile.dist Makefile

REM create curlbuild.h
copy include\curl\curlbuild.h.dist include\curl\curlbuild.h

REM setup c-ares CVS tree
if not exist ares\buildconf.bat goto end_c_ares
cd ares
call buildconf.bat
cd ..
:end_c_ares

