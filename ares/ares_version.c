/* $Id: ares_version.c,v 1.2 2004-01-29 12:07:34 bagder Exp $ */

#include "ares_version.h"

const char *ares_version(int *version)
{
  if(version)
    *version = ARES_VERSION;

  return ARES_VERSION_STR;
}
