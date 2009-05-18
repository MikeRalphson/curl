/* $Id: ares_library_init.c,v 1.2 2009-05-18 01:25:20 yangtse Exp $ */

#include "setup.h"

#include "ares.h"
#include "ares_library_init.h"
#include "ares_private.h"

/* library-private global and unique instance vars */

#ifdef WIN32
fpGetNetworkParams_t fpGetNetworkParams = ZERO_NULL;
fpSystemFunction036_t fpSystemFunction036 = ZERO_NULL;
#endif

/* library-private global vars with source visibility restricted to this file */

static unsigned int ares_initialized;
static int          ares_init_flags;

#ifdef WIN32
static HMODULE hnd_iphlpapi;
static HMODULE hnd_advapi32;
#endif


static int ares_win32_init(void)
{
#ifdef WIN32

  hnd_iphlpapi = 0;
  hnd_iphlpapi = LoadLibrary("iphlpapi.dll");
  if (!hnd_iphlpapi)
    return ARES_ELOADIPHLPAPI;

  fpGetNetworkParams = (fpGetNetworkParams_t)
    GetProcAddress(hnd_iphlpapi, "GetNetworkParams");
  if (!fpGetNetworkParams)
    {
      FreeLibrary(hnd_iphlpapi);
      return ARES_EADDRGetNetworkParams;
    }

  hnd_advapi32 = 0;
  hnd_advapi32 = LoadLibrary("advapi32.dll");
  if (!hnd_advapi32)
    {
      FreeLibrary(hnd_iphlpapi);
      return ARES_ELOADADVAPI32;
    }

  fpSystemFunction036 = (fpSystemFunction036_t)
    GetProcAddress(hnd_advapi32, "SystemFunction036");

  /*
   * Intentionally avoid checking if the address of SystemFunction036, a.k.a.
   * RtlGenRandom, has been located or not. This function is only available on
   * WinXP and later. When unavailable c-ares uses portable rand() function.
   */

#endif
  return ARES_SUCCESS;
}


static void ares_win32_cleanup(void)
{
#ifdef WIN32
  if (hnd_advapi32)
    FreeLibrary(hnd_advapi32);
  if (hnd_iphlpapi)
    FreeLibrary(hnd_iphlpapi);
#endif
}


int ares_library_init(int flags)
{
  int res;

  if (ares_initialized)
    return ARES_SUCCESS;
  ares_initialized++;

  if (flags & ARES_LIB_INIT_WIN32)
    {
      res = ares_win32_init();
      if (res != ARES_SUCCESS)
        return res;
    }

  ares_init_flags = flags;

  return ARES_SUCCESS;
}


void ares_library_cleanup(void)
{
  if (!ares_initialized)
    return;
  ares_initialized--;

  if (ares_init_flags & ARES_LIB_INIT_WIN32)
    ares_win32_cleanup();

  ares_init_flags = ARES_LIB_INIT_NONE;
}

