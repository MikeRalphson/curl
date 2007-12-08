/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id: lib549.c,v 1.1 2007-12-08 22:53:32 bagder Exp $
 *
 * argv1 = URL
 * argv2 = proxy
 * argv3 = non-zero means ASCII transfer
 */

#include "test.h"

int test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  curl_easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_PROXY_TRANSFER_MODE, 1);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, TRUE);
  if(libtest_arg3)
    /* enable ascii/text mode */
    curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, TRUE);

  res = curl_easy_perform(curl);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}

