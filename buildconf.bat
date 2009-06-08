@echo off
REM
REM $Id: buildconf.bat,v 1.9 2009-06-08 14:27:36 yangtse Exp $
REM
REM This batch file must be used to set up a CVS tree to build on
REM systems where there is no autotools support (i.e. Microsoft).
REM
REM This file is not included nor needed for curl's release
REM archives, neither for curl's daily snapshot archives.

if exist CVS-INFO goto start_doing
ECHO ERROR: This file shall only be used with a curl CVS tree checkout.
goto end_all
:start_doing

REM create hugehelp.c
if not exist src\hugehelp.c.cvs goto end_hugehelp_c
copy /Y src\hugehelp.c.cvs src\hugehelp.c
:end_hugehelp_c

REM create Makefile
if not exist Makefile.dist goto end_makefile
copy /Y Makefile.dist Makefile
:end_makefile

REM create curlbuild.h
if not exist include\curl\curlbuild.h.dist goto end_curlbuild_h
copy /Y include\curl\curlbuild.h.dist include\curl\curlbuild.h
:end_curlbuild_h

REM setup c-ares CVS tree
if not exist ares\buildconf.bat goto end_c_ares
cd ares
call buildconf.bat
cd ..
:end_c_ares

:end_all

