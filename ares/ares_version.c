/* $Id: ares_version.c,v 1.1 2003-10-24 20:28:04 bagder Exp $ */

#include "ares_version.h"

char *ares_version(int *version)
{
  if(version)
    *version = ARES_VERSION;

  return ARES_VERSION_STR;
}
