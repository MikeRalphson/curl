/* $Id: ares_version.c,v 1.4 2009-05-18 00:21:02 yangtse Exp $ */

#include "setup.h"
#include "ares.h"

const char *ares_version(int *version)
{
  if(version)
    *version = ARES_VERSION;

  return ARES_VERSION_STR;
}
