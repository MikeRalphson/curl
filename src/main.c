/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source: /cvsroot/curl/curl/src/main.c,v $
 * $Revision: 1.48 $
 * $Date: 2000-11-21 09:38:41 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <ctype.h>

#include <curl/curl.h>
#include <curl/types.h> /* new for v7 */
#include <curl/easy.h> /* new for v7 */

#define _MPRINTF_REPLACE /* we want curl-functions instead of native ones */
#include <curl/mprintf.h>

#include "urlglob.h"
#include "writeout.h"

#define CURLseparator	"--_curl_--"
#define MIMEseparator	"_curl_"

/* This define make use of the "Curlseparator" as opposed to the
   MIMEseparator. We might add support for the latter one in the
   future, and that's why this is left in the source. */
#define CURL_SEPARATORS

/* This is now designed to have its own local setup.h */
#include "setup.h"

#ifdef WIN32
#include <winsock.h>
#endif

#include "version.h"

#ifdef HAVE_IO_H /* typical win32 habit */
#include <io.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

/* The last #include file should be: */
#ifdef MALLOCDEBUG
/* this is low-level hard-hacking memory leak tracking shit */
#include "../lib/memdebug.h"
#endif

#define DEBUG_CONFIG

#ifndef __cplusplus        /* (rabe) */
typedef char bool;
#endif                     /* (rabe) */

typedef enum {
  HTTPREQ_UNSPEC,
  HTTPREQ_GET,
  HTTPREQ_HEAD,
  HTTPREQ_POST,
  HTTPREQ_SIMPLEPOST,
  HTTPREQ_CUSTOM,
  HTTPREQ_LAST
} HttpReq;

/* Just a set of bits */
#define CONF_DEFAULT  0

#define CONF_AUTO_REFERER (1<<4) /* the automatic referer-system please! */
#define CONF_VERBOSE  (1<<5) /* talk a lot */
#define CONF_HEADER   (1<<8) /* throw the header out too */
#define CONF_NOPROGRESS (1<<10) /* shut off the progress meter */
#define CONF_NOBODY   (1<<11) /* use HEAD to get http document */
#define CONF_FAILONERROR (1<<12) /* no output on http error codes >= 300 */
#define CONF_UPLOAD   (1<<14) /* this is an upload */
#define CONF_POST     (1<<15) /* HTTP POST method */
#define CONF_FTPLISTONLY (1<<16) /* Use NLST when listing ftp dir */
#define CONF_FTPAPPEND (1<<20) /* Append instead of overwrite on upload! */
#define CONF_NETRC    (1<<22)  /* read user+password from .netrc */
#define CONF_FOLLOWLOCATION (1<<23) /* use Location: Luke! */
#define CONF_GETTEXT  (1<<24) /* use ASCII/text for transfer */
#define CONF_HTTPPOST (1<<25) /* multipart/form-data HTTP POST */
#define CONF_PUT      (1<<27) /* PUT the input file */
#define CONF_MUTE     (1<<28) /* force NOPROGRESS */

#ifndef HAVE_STRDUP
/* Ultrix doesn't have strdup(), so make a quick clone: */
char *strdup(char *str)
{
  int len;
  char *newstr;

  len = strlen(str);
  newstr = (char *) malloc((len+1)*sizeof(char));
  if (!newstr)
    return (char *)NULL;

  strcpy(newstr,str);

  return newstr;

}
#endif 

extern void hugehelp(void);

/***********************************************************************
 * Start with some silly functions to make win32-systems survive
 ***********************************************************************/
#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
static void win32_cleanup(void)
{
  WSACleanup();
}

static CURLcode win32_init(void)
{
  WORD wVersionRequested;  
  WSADATA wsaData; 
  int err; 
  wVersionRequested = MAKEWORD(1, 1); 
    
  err = WSAStartup(wVersionRequested, &wsaData); 
    
  if (err != 0) 
    /* Tell the user that we couldn't find a useable */ 
    /* winsock.dll.     */ 
    return CURLE_FAILED_INIT; 
    
  /* Confirm that the Windows Sockets DLL supports 1.1.*/ 
  /* Note that if the DLL supports versions greater */ 
  /* than 1.1 in addition to 1.1, it will still return */ 
  /* 1.1 in wVersion since that is the version we */ 
  /* requested. */ 
    
  if ( LOBYTE( wsaData.wVersion ) != 1 || 
       HIBYTE( wsaData.wVersion ) != 1 ) { 
    /* Tell the user that we couldn't find a useable */ 

    /* winsock.dll. */ 
    WSACleanup(); 
    return CURLE_FAILED_INIT; 
  }
  return CURLE_OK;
}
/* The Windows Sockets DLL is acceptable. Proceed. */ 
#else
static CURLcode win32_init(void) { return CURLE_OK; }
#define win32_cleanup()
#endif


/*
 * This is the main global constructor for the app. Call this before
 * _any_ libcurl usage. If this fails, *NO* libcurl functions may be
 * used, or havoc may be the result.
 */
CURLcode main_init(void)
{
  return win32_init();
}

/*
 * This is the main global destructor for the app. Call this after
 * _all_ libcurl usage is done.
 */
void main_free(void)
{
  win32_cleanup();
}

int SetHTTPrequest(HttpReq req, HttpReq *store)
{
  if((*store == HTTPREQ_UNSPEC) ||
     (*store == req)) {
    *store = req;
    return 0;
  }
  fprintf(stderr, "You can only select one HTTP request!\n");
  return 1;
}

static void helpf(char *fmt, ...)
{
  va_list ap;
  if(fmt) {
    va_start(ap, fmt);
    fputs("curl: ", stderr); /* prefix it */
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  }
  fprintf(stderr, "curl: try 'curl --help' for more information\n");
}

static void help(void)
{
  printf(CURL_ID "%s\n"
       "Usage: curl [options...] <url>\n"
       "Options: (H) means HTTP/HTTPS only, (F) means FTP only\n"
       " -a/--append        Append to target file when uploading (F)\n"
       " -A/--user-agent <string> User-Agent to send to server (H)\n"
       " -b/--cookie <name=string/file> Cookie string or file to read cookies from (H)\n"
       " -B/--use-ascii     Use ASCII/text transfer\n"
       " -c/--continue      Resume a previous transfer where we left it\n"
       " -C/--continue-at <offset> Specify absolute resume offset\n"
       " -d/--data <data>   HTTP POST data (H)\n"
       "    --data-ascii <data>   HTTP POST ASCII data (H)\n"
       "    --data-binary <data>  HTTP POST binary data (H)\n"
       " -D/--dump-header <file> Write the headers to this file\n"
       " -e/--referer       Referer page (H)\n"
       " -E/--cert <cert:passwd> Specifies your certificate file and password (HTTPS)\n"
       " -f/--fail          Fail silently (no output at all) on errors (H)\n"
       " -F/--form <name=content> Specify HTTP POST data (H)\n"

       " -h/--help          This help text\n"
       " -H/--header <line> Custom header to pass to server. (H)\n"
       " -i/--include       Include the HTTP-header in the output (H)\n"
       " -I/--head          Fetch document info only (HTTP HEAD/FTP SIZE)\n"
       "    --interface <interface> Specify the interface to be used\n"
       "    --krb4 <level>  Enable krb4 with specified security level (F)\n"
       " -K/--config        Specify which config file to read\n"
       " -l/--list-only     List only names of an FTP directory (F)\n"
       " -L/--location      Follow Location: hints (H)\n"
       " -m/--max-time <seconds> Maximum time allowed for the transfer\n"
       " -M/--manual        Display huge help text\n"
       " -n/--netrc         Read .netrc for user name and password\n"
       " -N/--no-buffer     Disables the buffering of the output stream\n"
       " -o/--output <file> Write output to <file> instead of stdout\n"
       " -O/--remote-name   Write output to a file named as the remote file\n"
       " -p/--proxytunnel   Perform non-HTTP services through a HTTP proxy\n"
       " -P/--ftpport <address> Use PORT with address instead of PASV when ftping (F)\n"
       " -q                 When used as the first parameter disables .curlrc\n"
       " -Q/--quote <cmd>   Send QUOTE command to FTP before file transfer (F)\n"
       " -r/--range <range> Retrieve a byte range from a HTTP/1.1 or FTP server\n"
       " -s/--silent        Silent mode. Don't output anything\n"
       " -S/--show-error    Show error. With -s, make curl show errors when they occur\n"
       " -t/--upload        Transfer/upload stdin to remote site\n"
       " -T/--upload-file <file> Transfer/upload <file> to remote site\n"
       " -u/--user <user:password> Specify user and password to use\n"
       " -U/--proxy-user <user:password> Specify Proxy authentication\n"
       " -v/--verbose       Makes the operation more talkative\n"
       " -V/--version       Outputs version number then quits\n"
       " -w/--write-out [format] What to output after completion\n"
       " -x/--proxy <host[:port]>  Use proxy. (Default port is 1080)\n"
       " -X/--request <command> Specific request command to use\n"
       " -y/--speed-time    Time needed to trig speed-limit abort. Defaults to 30\n"
       " -Y/--speed-limit   Stop transfer if below speed-limit for 'speed-time' secs\n"
       " -z/--time-cond <time> Includes a time condition to the server (H)\n"
       " -2/--sslv2         Force usage of SSLv2 (H)\n"
       " -3/--sslv3         Force usage of SSLv3 (H)\n"
       " -#/--progress-bar  Display transfer progress as a progress bar\n"
       "    --crlf          Convert LF to CRLF in upload. Useful for MVS (OS/390)\n"
       "    --stderr <file> Where to redirect stderr. - means stdout.\n",
         curl_version()
         );
}

struct LongShort {
  char *letter;
  char *lname;
  bool extraparam;
};

struct Configurable {
  char *useragent;
  char *cookie;
  bool use_resume;
  int resume_from;
  char *postfields;
  long postfieldsize;
  char *referer;
  long timeout;
  char *outfile;
  char *headerfile;
  char remotefile;
  char *ftpport;
  char *iface;
  unsigned short porttouse;
  char *range;
  int low_speed_limit;
  int low_speed_time;
  bool showerror;
  char *infile;
  char *userpwd;
  char *proxyuserpwd;
  char *proxy;
  bool configread;
  bool proxytunnel;
  long conf;
  char *url;
  char *cert;
  char *cert_passwd;
  bool crlf;
  char *cookiefile;
  char *customrequest;
  char *krb4level;
  bool progressmode;
  bool nobuffer;

  char *writeout; /* %-styled format string to output */

  FILE *errors; /* if stderr redirect is requested */

  struct curl_slist *quote;
  struct curl_slist *postquote;

  long ssl_version;
  TimeCond timecond;
  time_t condtime;

  struct curl_slist *headers;

  struct HttpPost *httppost;
  struct HttpPost *last_post;

  HttpReq httpreq;
};

static int parseconfig(char *filename,
		       struct Configurable *config);
static char *my_get_line(FILE *fp);

static void GetStr(char **string,
		   char *value)
{
  if(*string)
    free(*string);
  if(value && *value)
    *string = strdup(value);
  else
    *string = NULL;
}

static char *file2string(FILE *file)
{
  char buffer[256];
  char *ptr;
  char *string=NULL;
  int len=0;
  int stringlen;

  if(file) {
    while(fgets(buffer, sizeof(buffer), file)) {
      ptr= strchr(buffer, '\r');
      if(ptr)
        *ptr=0;
      ptr= strchr(buffer, '\n');
      if(ptr)
        *ptr=0;
      stringlen=strlen(buffer);
      if(string)
        string = realloc(string, len+stringlen+1);
      else
        string = malloc(stringlen+1);

      strcpy(string+len, buffer);

      len+=stringlen;
    }
    return string;
  }
  else
    return NULL; /* no string */
}

static char *file2memory(FILE *file, long *size)
{
  char buffer[1024];
  char *string=NULL;
  char *newstring=NULL;
  long len=0;
  long stringlen=0;

  if(file) {
    while((len = fread(buffer, 1, sizeof(buffer), file))) {
      if(string) {
        newstring = realloc(string, len+stringlen);
        if(newstring)
          string = newstring;
        else
          break; /* no more strings attached! :-) */
      }
      else
        string = malloc(len);
      memcpy(&string[stringlen], buffer, len);
      stringlen+=len;
    }
    *size = stringlen;
    return string;
  }
  else
    return NULL; /* no string */
}

typedef enum {
  PARAM_OK,
  PARAM_OPTION_AMBIGUOUS,
  PARAM_OPTION_UNKNOWN,
  PARAM_REQUIRES_PARAMETER,  
  PARAM_BAD_USE,
  PARAM_HELP_REQUESTED,
  PARAM_GOT_EXTRA_PARAMETER,

  PARAM_LAST
} ParameterError;

static ParameterError getparameter(char *flag, /* f or -long-flag */
                                   char *nextarg, /* NULL if unset */
                                   bool *usedarg, /* set to TRUE if the arg
                                                     has been used */
                                   struct Configurable *config)
{
  char letter;
  char subletter=0; /* subletters can only occur on long options */

  char *parse=NULL;
  int res;
  int j;
  time_t now;
  int hit=-1;
  bool longopt=FALSE;

  /* single-letter,
     long-name,
     boolean whether it takes an additional argument
     */
  struct LongShort aliases[]= {
    {"9", "crlf",        FALSE},
    {"8", "stderr",      TRUE},
    {"7", "interface",   TRUE},
    {"6", "krb4",        TRUE},
    {"5", "url",         TRUE},

    {"2", "sslv2",       FALSE},
    {"3", "sslv3",       FALSE},
    {"a", "append",      FALSE},
    {"A", "user-agent",  TRUE},
    {"b", "cookie",      TRUE},
    {"B", "ftp-ascii",   FALSE}, /* this long format is OBSOLETEE now! */
    {"B", "use-ascii",   FALSE},
    {"c", "continue",    FALSE},
    {"C", "continue-at", TRUE},
    {"d", "data",        TRUE},
    {"da", "data-ascii", TRUE},
    {"db", "data-binary", TRUE},
    {"D", "dump-header", TRUE},
    {"e", "referer",     TRUE},
    {"E", "cert",        TRUE},
    {"f", "fail",        FALSE},
    {"F", "form",        TRUE},

    {"h", "help",        FALSE},
    {"H", "header",      TRUE},
    {"i", "include",     FALSE},
    {"I", "head",        FALSE},
    {"K", "config",      TRUE},
    {"l", "list-only",   FALSE},
    {"L", "location",    FALSE},
    {"m", "max-time",    TRUE},
    {"M", "manual",      FALSE},
    {"n", "netrc",       FALSE},
    {"N", "no-buffer",   FALSE},
    {"o", "output",      TRUE},
    {"O", "remote-name", FALSE},
    {"p", "proxytunnel", FALSE},
    {"P", "ftpport",     TRUE},
    {"q", "disable",     FALSE},
    {"Q", "quote",       TRUE},
    {"r", "range",       TRUE},
    {"s", "silent",      FALSE},
    {"S", "show-error",  FALSE},
    {"t", "upload",      FALSE},
    {"T", "upload-file", TRUE},
    {"u", "user",        TRUE},
    {"U", "proxy-user",  TRUE},
    {"v", "verbose",     FALSE},
    {"V", "version",     FALSE},
    {"w", "write-out",   TRUE},
    {"x", "proxy",       TRUE},
    {"X", "request",     TRUE},
    {"X", "http-request", TRUE}, /* OBSOLETE VERSION */
    {"Y", "speed-limit",  TRUE},
    {"y", "speed-time", TRUE},
    {"z", "time-cond",   TRUE},
    {"#", "progress-bar",FALSE},
  };

  if(('-' != flag[0]) ||
     (('-' == flag[0]) && ('-' == flag[1]))) {
    /* this should be a long name */
    char *word=('-' == flag[0])?flag+2:flag;
    int fnam=strlen(word);
    int numhits=0;
    for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(strnequal(aliases[j].lname, word, fnam)) {
        longopt = TRUE;
        numhits++;
        if(strequal(aliases[j].lname, word)) {
          parse = aliases[j].letter;
          hit = j;
          numhits = 1; /* a single unique hit */
          break;
        }
	parse = aliases[j].letter;
	hit = j;
      }
    }
    if(numhits>1) {
      /* this is at least the second match! */
      return PARAM_OPTION_AMBIGUOUS;
    }
    if(hit < 0) {
      return PARAM_OPTION_UNKNOWN;
    }    
  }
  else {
    flag++; /* prefixed with one dash, pass it */
    hit=-1;
    parse = flag;
  }

  do {
    /* we can loop here if we have multiple single-letters */

    if(!longopt)
      letter = parse?*parse:'\0';
    else {
      letter = parse[0];
      subletter = parse[1];
    }
    *usedarg = FALSE; /* default is that we don't use the arg */

#if 0
    fprintf(stderr, "OPTION: %c %s\n", letter, nextarg?nextarg:"<null>");
#endif
    if(hit < 0) {
      for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
	if(letter == aliases[j].letter[0]) {
	  hit = j;
	  break;
	}
      }
      if(hit < 0) {
	return PARAM_OPTION_UNKNOWN;
      }
    }
    if(hit < 0) {
      return PARAM_OPTION_UNKNOWN;
    }    
    if((!nextarg || !*nextarg) && aliases[hit].extraparam) {
      return PARAM_REQUIRES_PARAMETER;
    }
    else if(nextarg && aliases[hit].extraparam)
      *usedarg = TRUE; /* mark it as used */

    switch(letter) {
    case 'z': /* time condition coming up */
      switch(*nextarg) {
      case '+':
        nextarg++;
      default:
        /* If-Modified-Since: (section 14.28 in RFC2068) */
        config->timecond = TIMECOND_IFMODSINCE;
        break;
      case '-':
        /* If-Unmodified-Since:  (section 14.24 in RFC2068) */
        config->timecond = TIMECOND_IFUNMODSINCE;
        nextarg++;
        break;
      case '=':
        /* Last-Modified:  (section 14.29 in RFC2068) */
        config->timecond = TIMECOND_LASTMOD;
        nextarg++;
        break;
      }
      now=time(NULL);
      config->condtime=curl_getdate(nextarg, &now);
      if(-1 == config->condtime) {
        /* now let's see if it is a file name to get the time from instead! */
        struct stat statbuf;
        if(-1 == stat(nextarg, &statbuf)) {
          /* failed, remove time condition */
          config->timecond = TIMECOND_NONE;
        }
        else {
          /* pull the time out from the file */
          config->condtime = statbuf.st_mtime;
        }
      }
      break;
    case '9': /* there is no short letter for this */
      /* LF -> CRLF conversinon? */
      config->crlf = TRUE;
      break;
    case '8': /* there is no short letter for this */
      if(strcmp(nextarg, "-"))
        config->errors = fopen(nextarg, "wt");
      else
        config->errors = stdout;
      break;
    case '7': /* there is no short letter for this */
      /* interface */
      GetStr(&config->iface, nextarg);
      break;
    case '6': /* there is no short letter for this */
      /* krb4 level string */
      GetStr(&config->krb4level, nextarg);
      break;
    case '5':
      /* the URL! */
      GetStr(&config->url, nextarg);
      break;
    case '#': /* added 19990617 larsa */
      config->progressmode ^= CURL_PROGRESS_BAR;
      break;
    case '2': 
      /* SSL version 2 */
      config->ssl_version = 2;
      break;
    case '3': 
      /* SSL version 2 */
      config->ssl_version = 3;
      break;
    case 'a':
      /* This makes the FTP sessions use APPE instead of STOR */
      config->conf ^= CONF_FTPAPPEND;
      break;
    case 'A':
      /* This specifies the User-Agent name */
      GetStr(&config->useragent, nextarg);
      break;
    case 'b': /* cookie string coming up: */
      if(nextarg[0] == '@') {
        nextarg++;
      }
      else if(strchr(nextarg, '=')) {
        /* A cookie string must have a =-letter */
        GetStr(&config->cookie, nextarg);
        break;
      }
      /* We have a cookie file to read from! */
      GetStr(&config->cookiefile, nextarg);
      break;
    case 'B':
      /* use ASCII/text when transfering */
      config->conf ^= CONF_GETTEXT;
      break;
    case 'c':
      /* This makes us continue an ftp transfer */
      config->use_resume^=TRUE;
      fprintf(stderr, "-c is a deprecated switch, use '-C -' instead!\n");
      break;
    case 'C':
      /* This makes us continue an ftp transfer at given position */
      if(!strequal(nextarg, "-"))
        config->resume_from= atoi(nextarg);
      config->use_resume=TRUE;
      break;
    case 'd':
      /* postfield data */
      {
        char *postdata=NULL;

        if('@' == *nextarg) {
          /* the data begins with a '@' letter, it means that a file name
             or - (stdin) follows */
          FILE *file;

          nextarg++; /* pass the @ */

          if(strequal("-", nextarg))
            file = stdin;
          else 
            file = fopen(nextarg, "r");

          if(subletter == 'b') /* forced binary */
            postdata = file2memory(file, &config->postfieldsize);
          else
            postdata = file2string(file);
          if(file && (file != stdin))
            fclose(stdin);
        }
        else {
          GetStr(&postdata, nextarg);
        }

        if(config->postfields && *config->postfields) {
          /* we already have a string, we append this one
             with a separating &-letter */
          char *oldpost=config->postfields;
          config->postfields=maprintf("%s&%s", oldpost, postdata);
          free(oldpost);
          free(postdata);
        }
        else
          config->postfields=postdata;
      }
      if(config->postfields)
        config->conf |= CONF_POST;
      if(SetHTTPrequest(HTTPREQ_SIMPLEPOST, &config->httpreq))
        return PARAM_BAD_USE;
      break;
    case 'D':
      /* dump-header to given file name */
      GetStr(&config->headerfile, nextarg);
      break;
    case 'e':
      {
        char *ptr = strstr(nextarg, ";auto");
        if(ptr) {
          /* Automatic referer requested, this may be combined with a
             set initial one */
          config->conf |= CONF_AUTO_REFERER;
          *ptr = 0; /* zero terminate here */
        }
        GetStr(&config->referer, nextarg);
      }
      break;
    case 'E':
      {
	char *ptr = strchr(nextarg, ':');
	if(ptr) {
	  /* we have a password too */
	  *ptr=0;
	  ptr++;
	  GetStr(&config->cert_passwd, ptr);
	}
	GetStr(&config->cert, nextarg);
      }
      break;
    case 'f':
      /* fail hard on errors  */
      config->conf ^= CONF_FAILONERROR;
      break;
    case 'F':
      /* "form data" simulation, this is a little advanced so lets do our best
	 to sort this out slowly and carefully */
      if(curl_formparse(nextarg,
                        &config->httppost,
                        &config->last_post))
	return PARAM_BAD_USE;
      if(SetHTTPrequest(HTTPREQ_POST, &config->httpreq))
        return PARAM_BAD_USE;
      break;

    case 'h': /* h for help */
      help();
      return PARAM_HELP_REQUESTED;
    case 'H':
      /* A custom header to append to a list */
      config->headers = curl_slist_append(config->headers, nextarg);
      break;
    case 'i':
      config->conf ^= CONF_HEADER; /* include the HTTP header as well */
      break;
    case 'I':
      config->conf ^= CONF_HEADER; /* include the HTTP header in the output */
      config->conf ^= CONF_NOBODY; /* don't fetch the body at all */
      if(SetHTTPrequest(HTTPREQ_HEAD, &config->httpreq))
        return PARAM_BAD_USE;
      break;
    case 'K':
      res = parseconfig(nextarg, config);
      config->configread = TRUE;
      if(res)
	return res;
      break;
    case 'l':
      config->conf ^= CONF_FTPLISTONLY; /* only list the names of the FTP dir */
      break;
    case 'L':
      config->conf ^= CONF_FOLLOWLOCATION; /* Follow Location: HTTP headers */
      break;
    case 'm':
      /* specified max time */
      config->timeout = atoi(nextarg);
      break;
    case 'M': /* M for manual, huge help */
      hugehelp();
      return PARAM_HELP_REQUESTED;
    case 'n':
      /* pick info from .netrc, if this is used for http, curl will
	 automatically enfore user+password with the request */
      config->conf ^= CONF_NETRC;
      break;
    case 'N':
      /* disable the output I/O buffering */
      config->nobuffer ^= 1;
      break;
    case 'o':
      /* output file */
      GetStr(&config->outfile, nextarg); /* write to this file */
      break;
    case 'O':
      /* output file */
      config->remotefile ^= TRUE;
      break;
    case 'P':
      /* This makes the FTP sessions use PORT instead of PASV */
      /* use <eth0> or <192.168.10.10> style addresses. Anything except
	 this will make us try to get the "default" address.
	 NOTE: this is a changed behaviour since the released 4.1!
	 */
      GetStr(&config->ftpport, nextarg);
      break;
    case 'p':
      /* proxy tunnel for non-http protocols */
      config->proxytunnel ^= TRUE;
      break;

    case 'q': /* if used first, already taken care of, we do it like
		 this so we don't cause an error! */
      break;
    case 'Q':
      /* QUOTE command to send to FTP server */
      if(nextarg[0] == '-') {
        /* prefixed with a dash makes it a POST TRANSFER one */
        nextarg++;
        config->postquote = curl_slist_append(config->postquote, nextarg);
      }
      else {
        config->quote = curl_slist_append(config->quote, nextarg);
      }
      break;
    case 'r':
      /* byte range requested */
      GetStr(&config->range, nextarg);
      break;
    case 's':
      /* don't show progress meter, don't show errors : */
      config->conf |= (CONF_MUTE|CONF_NOPROGRESS);
      config->showerror ^= TRUE; /* toggle off */
      break;
    case 'S':
      /* show errors */
      config->showerror ^= TRUE; /* toggle on if used with -s */
      break;
    case 't':
      /* we are uploading */
      config->conf ^= CONF_UPLOAD;
      fprintf(stderr, "-t is a deprecated switch, use '-T -' instead!\n");
      break;
    case 'T':
      /* we are uploading */
      config->conf |= CONF_UPLOAD;
      if(!strequal("-", nextarg))
        /* make - equal stdin */
        GetStr(&config->infile, nextarg);
      break;
    case 'u':
      /* user:password  */
      GetStr(&config->userpwd, nextarg);
      break;
    case 'U':
      /* Proxy user:password  */
      GetStr(&config->proxyuserpwd, nextarg);
      break;
    case 'v':
      config->conf ^= CONF_VERBOSE; /* talk a lot */
      break;
    case 'V':
      printf(CURL_ID "%s\n", curl_version());
      return PARAM_HELP_REQUESTED;
    case 'w':
      /* get the output string */
      if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a file name
           or - (stdin) follows */
        FILE *file;
        nextarg++; /* pass the @ */
        if(strequal("-", nextarg))
          file = stdin;
        else 
          file = fopen(nextarg, "r");
        config->writeout = file2string(file);
        if(file && (file != stdin))
          fclose(stdin);
      }
      else 
        GetStr(&config->writeout, nextarg);
      break;
    case 'x':
      /* proxy */
      GetStr(&config->proxy, nextarg);
      break;
    case 'X':
      /* HTTP request */
      GetStr(&config->customrequest, nextarg);
      if(SetHTTPrequest(HTTPREQ_CUSTOM, &config->httpreq))
        return PARAM_BAD_USE;
      break;
    case 'y':
      /* low speed time */
      config->low_speed_time = atoi(nextarg);
      if(!config->low_speed_limit)
	config->low_speed_limit = 1;
      break;
    case 'Y':
      /* low speed limit */
      config->low_speed_limit = atoi(nextarg);
      if(!config->low_speed_time)
	config->low_speed_time=30;
      break;

    default: /* unknown flag */
      return PARAM_OPTION_UNKNOWN;
    }
    hit = -1;

  } while(*++parse && !*usedarg);

  return PARAM_OK;
}


static int parseconfig(char *filename,
		       struct Configurable *config)
{
  int res;
  FILE *file;
  char filebuffer[256];
  bool usedarg;
  char *home=NULL;
  
  if(!filename || !*filename) {
    /* NULL or no file name attempts to load .curlrc from the homedir! */

#define CURLRC DOT_CHAR "curlrc"

    home = curl_getenv("HOME"); /* portable environment reader */

    if(!home)
      return 0;
    if(strlen(home)>(sizeof(filebuffer)-strlen(CURLRC))) {
      free(home);
      return 0;
    }

    sprintf(filebuffer, "%s%s%s", home, DIR_CHAR, CURLRC);

    filename = filebuffer;
  }

  if(strcmp(filename,"-"))
    file = fopen(filename, "r");
  else
    file = stdin;
  
  if(file) {
    char *line;
    char *aline;
    char *option;
    char *param;
    int lineno=0;
    bool alloced_param;

#define isseparator(x) (((x)=='=') || ((x) == ':'))

    while (NULL != (aline = my_get_line(file))) {
      lineno++;
      line = aline;
      alloced_param=FALSE;

      /* lines with # in the fist column is a comment! */
      while(isspace((int)*line))
        line++;

      switch(*line) {
      case '#':
      case '/':
      case '\r':
      case '\n':
      case '*':
      case '\0':
        free(line);
        continue;
      }

      /* the option keywords starts here */
      option = line;
      while(*line && !isspace((int)*line) && !isseparator(*line))
        line++;
      /* ... and has ended here */

      *line++=0; /* zero terminate, we have a local copy of the data */

#ifdef DEBUG_CONFIG
      fprintf(stderr, "GOT: %s\n", option);
#endif

      /* pass spaces and separator(s) */
      while(isspace((int)*line) || isseparator(*line))
        line++;
      
      /* the parameter starts here (unless quoted) */
      if(*line == '\"') {
        char *ptr;
        /* quoted parameter, do the qoute dance */
        line++;
        param=strdup(line); /* parameter */
        alloced_param=TRUE;

        ptr=param;
        while(*line && (*line != '\"')) {
          if(*line == '\\') {
            char out;
            line++;

            /* default is to output the letter after the backslah */
            switch(out = *line) {
            case '\0':
              continue; /* this'll break out of the loop */
            case 't':
              out='\t';
              break;
            case 'n':
              out='\n';
              break;
            case 'r':
              out='\r';
              break;
            case 'v':
              out='\v';
              break;
            }
            *ptr++=out;
            line++;
          }
          else
            *ptr++=*line++;
        }
        *ptr=0; /* always zero terminate */

      }
      else {
        param=line; /* parameter starts here */
        while(*line && !isspace((int)*line))
          line++;
        *line=0; /* zero terminate */
      }
#ifdef DEBUG_CONFIG
      fprintf(stderr, "PARAM: \"%s\"\n", param);
#endif
      res = getparameter(option, param, &usedarg, config);

      if(*param && !usedarg)
        /* we passed in a parameter that wasn't used! */
        res = PARAM_GOT_EXTRA_PARAMETER;

      if(res != PARAM_OK) {
        /* the help request isn't really an error */
        if(!strcmp(filename, "-")) {
          filename="<stdin>";
        }
        if(PARAM_HELP_REQUESTED != res) {
          char *reason;
          switch(res) {
          default:
          case PARAM_GOT_EXTRA_PARAMETER:
            reason = "had unsupported trailing garbage";
            break;
          case PARAM_OPTION_UNKNOWN:
            reason = "is unknown";
            break;
          case PARAM_OPTION_AMBIGUOUS:
            reason = "is ambiguous";
            break;
          case PARAM_REQUIRES_PARAMETER:
            reason = "requires parameter";
            break;
          case PARAM_BAD_USE:
            reason = "is badly used here";
            break;
          }
          fprintf(stderr, "%s:%d: warning: '%s' %s\n",
                  filename, lineno, option, reason);
        }
      }

      if(alloced_param)
        free(param);

      free(aline);
    }
    if(file != stdin)
      fclose(file);
  }
  if(home)
    free(home);
  return 0;
}

struct OutStruct {
  char *filename;
  FILE *stream;
};

/* having this global is a bit dirty, but hey, who said we weren't? ;-) */
struct Configurable config;

int my_fwrite(void *buffer, size_t size, size_t nmemb, FILE *stream)
{
  struct OutStruct *out=(struct OutStruct *)stream;
  if(out && !out->stream) {
    /* open file for writing */
    out->stream=fopen(out->filename, "wb");
    if(!out->stream)
      return -1; /* failure */
    if(config.nobuffer) {
      /* disable output buffering */
#ifdef HAVE_SETVBUF
      setvbuf(out->stream, NULL, _IONBF, 0);
#endif
    }
  }
  return fwrite(buffer, size, nmemb, out->stream);
}

struct ProgressData {
  size_t total;
  size_t prev;
  size_t point;
  int width;
};

int myprogress (void *clientp,
                size_t dltotal,
                size_t dlnow,
                size_t ultotal,
                size_t ulnow)
{
  /* The original progress-bar source code was written for curl by Lars Aas,
     and this new edition inherites some of his concepts. */
  
  char line[256];
  char outline[256];
  char format[40];
  float frac;
  float percent;
  int barwidth;
  int num;
  int i;

  struct ProgressData *bar = (struct ProgressData *)clientp;
  size_t total = dltotal + ultotal;

  bar->point = dlnow + ulnow; /* we've come this far */

  if(0 == total) {
    int prevblock = bar->prev / 1024;
    int thisblock = bar->point / 1024;
    while ( thisblock > prevblock ) {
      fprintf( stderr, "#" );
      prevblock++;
    }
  }
  else {
    frac = (float) bar->point / (float) total;
    percent = frac * 100.0f;
    barwidth = bar->width - 7;
    num = (int) (((float)barwidth) * frac);
    i = 0;
    for ( i = 0; i < num; i++ ) {
      line[i] = '#';
    }
    line[i] = '\0';
    sprintf( format, "%%-%ds %%5.1f%%%%", barwidth );
    sprintf( outline, format, line, percent );
    fprintf( stderr, "\r%s", outline );
  }
  bar->prev = bar->point;

  return 0;
}

void progressbarinit(struct ProgressData *bar)
{
#ifdef __EMX__
  /* 20000318 mgs */
  int scr_size [2];
#endif
  char *colp;

  memset(bar, 0, sizeof(struct ProgressData));

/* TODO: get terminal width through ansi escapes or something similar.
         try to update width when xterm is resized... - 19990617 larsa */
#ifndef __EMX__
  /* 20000318 mgs
   * OS/2 users most likely won't have this env var set, and besides that
   * we're using our own way to determine screen width */
  colp = curl_getenv("COLUMNS");
  if (colp != NULL) {
    bar->width = atoi(colp);
    free(colp);
  }
  else
    bar->width = 79;
#else
  /* 20000318 mgs
   * We use this emx library call to get the screen width, and subtract
   * one from what we got in order to avoid a problem with the cursor
   * advancing to the next line if we print a string that is as long as
   * the screen is wide. */
 
  _scrsize(scr_size);
  bar->width = scr_size[0] - 1;
#endif

}

void free_config_fields(struct Configurable *confp)
{
  if(confp->url)
    free(confp->url);
  if(confp->userpwd)
    free(confp->userpwd);
  if(confp->postfields)
    free(confp->postfields);
  if(confp->proxy)
    free(confp->proxy);
  if(confp->proxyuserpwd)
    free(confp->proxyuserpwd);
  if(confp->cookie)
    free(confp->cookie);
  if(confp->cookiefile)
    free(confp->cookiefile);
  if(confp->krb4level)
    free(confp->krb4level);
  if(confp->headerfile)
    free(confp->headerfile);
  if(confp->outfile)
    free(confp->outfile);
  if(confp->infile)
    free(confp->infile);
  if(confp->range)
    free(confp->range);
  if(confp->customrequest)
    free(confp->customrequest);
  if(confp->writeout)
    free(confp->writeout);
  if(confp->httppost)
    curl_formfree(confp->httppost);

  curl_slist_free_all(confp->quote); /* the checks for confp->quote == NULL */
  curl_slist_free_all(confp->postquote); /*  */
  curl_slist_free_all(confp->headers); /*  */
}


static int 
operate(int argc, char *argv[])
{
  char errorbuffer[CURL_ERROR_SIZE];
  char useragent[128]; /* buah, we don't want a larger default user agent */
  struct ProgressData progressbar;

  struct OutStruct outs;
  struct OutStruct heads;

  char *url = NULL;

  URLGlob *urls;
  int urlnum;
  char *outfiles;
  int separator = 0;
  
  FILE *infd = stdin;
  FILE *headerfilep = NULL;
  char *urlbuffer=NULL;
  int infilesize=-1; /* -1 means unknown */
  bool stillflags=TRUE;

  bool allocuseragent=FALSE;

  CURL *curl;
  int res;
  int i;

  outs.stream = stdout;

#ifdef MALLOCDEBUG
  /* this sends all memory debug messages to a logfile named memdump */
  curl_memdebug("memdump");
#endif

  config.showerror=TRUE;
  config.conf=CONF_DEFAULT;
#if 0
  config.crlf=FALSE;
  config.quote=NULL;
#endif

  if(argc>1 &&
     (!strnequal("--", argv[1], 2) && (argv[1][0] == '-')) &&
     strchr(argv[1], 'q')) {
    /*
     * The first flag, that is not a verbose name, but a shortname
     * and it includes the 'q' flag!
     */
#if 0
    fprintf(stderr, "I TURNED OFF THE CRAP\n");
#endif
    ;
  }
  else {
    res = parseconfig(NULL, &config);
    if(res)
      return res;
  }

  if ((argc < 2)  && !config.url) {
    helpf(NULL);
    return CURLE_FAILED_INIT;
  }

  /* Parse options */
  for (i = 1; i < argc; i++) {
    if(stillflags &&
       ('-' == argv[i][0])) {
      char *nextarg;
      bool passarg;
      char *origopt=argv[i];
      
      char *flag = argv[i];

      if(strequal("--", argv[i]))
	/* this indicates the end of the flags and thus enables the
	   following (URL) argument to start with -. */
	stillflags=FALSE;
      else {
	nextarg= (i < argc - 1)? argv[i+1]: NULL;

	res = getparameter(flag, nextarg, &passarg, &config);
	if(res) {
          switch(res) {
          case PARAM_OPTION_AMBIGUOUS:
            helpf("option %s is ambiguous\n", origopt);
            break;
          case PARAM_OPTION_UNKNOWN:
            helpf("option %s is unknown\n", origopt);
            break;
          case PARAM_REQUIRES_PARAMETER:
            helpf("option %s requires an extra argument!\n", origopt);
            break;
          case PARAM_BAD_USE:
            helpf("option %s was wrongly used!\n", origopt);
            break;
          case PARAM_HELP_REQUESTED:
            /* no text */
            break;
          }
	  return CURLE_FAILED_INIT;
        }

	if(passarg) /* we're supposed to skip this */
	  i++;
      }
    }
    else {
      if(url) {
	helpf("only one URL is supported!\n");
	return CURLE_FAILED_INIT;
      }
      url = argv[i];
    }
  }

  /* if no URL was specified and there was one in the config file, get that
     one */
  if(!url && config.url)
    url = config.url;
  
  if(!url) {
    helpf("no URL specified!\n");
    return CURLE_FAILED_INIT;
  }
  if(NULL == config.useragent) {
    /* set non-zero default values: */
    snprintf(useragent, sizeof(useragent),
             CURL_NAME "/" CURL_VERSION " (" OS ") " "%s", curl_version());
    config.useragent= useragent;
  }
  else
    allocuseragent = TRUE;
#if 0
  fprintf(stderr, "URL: %s PROXY: %s\n", url, config.proxy?config.proxy:"none");
#endif

  /* expand '{...}' and '[...]' expressions and return total number of URLs
     in pattern set */
  res = glob_url(&urls, url, &urlnum);
  if(res != CURLE_OK)
    return res;

  /* save outfile pattern befor expansion */
  outfiles = config.outfile?strdup(config.outfile):NULL;

  if (!outfiles && !config.remotefile && urlnum > 1) {
#ifdef CURL_SEPARATORS
    /* multiple files extracted to stdout, insert separators! */
    separator = 1;
#endif
#ifdef MIME_SEPARATORS
    /* multiple files extracted to stdout, insert MIME separators! */
    separator = 1;
    printf("MIME-Version: 1.0\n");
    printf("Content-Type: multipart/mixed; boundary=%s\n\n", MIMEseparator);
#endif
  }
  for (i = 0; (url = next_url(urls)); ++i) {
    if (outfiles) {
      free(config.outfile);
      config.outfile = outfiles;
    }
 
    if (config.outfile || config.remotefile) {
      /* 
       * We have specified a file name to store the result in, or we have
       * decided we want to use the remote file name.
       */
      
      if(!config.outfile && config.remotefile) {
        /* Find and get the remote file name */
        config.outfile=strstr(url, "://");
        if(config.outfile)
          config.outfile+=3;
        else
          config.outfile=url;
        config.outfile = strdup(strrchr(config.outfile, '/'));
        if(!config.outfile || !strlen(++config.outfile)) {
          helpf("Remote file name has no length!\n");
          return CURLE_WRITE_ERROR;
        }
      }
      else {
	/* fill '#1' ... '#9' terms from URL pattern */
        char *outfile = config.outfile;
        config.outfile = match_url(config.outfile, *urls);
        free(outfile);
      }
      
      if((0 == config.resume_from) && config.use_resume) {
        /* we're told to continue where we are now, then we get the size of the
           file as it is now and open it for append instead */
        struct stat fileinfo;

        if(0 == stat(config.outfile, &fileinfo)) {
          /* set offset to current file size: */
          config.resume_from = fileinfo.st_size;
        }
        /* else let offset remain 0 */
      }
      
      if(config.resume_from) {
        /* open file for output: */
        outs.stream=(FILE *) fopen(config.outfile, config.resume_from?"ab":"wb");
        if (!outs.stream) {
          helpf("Can't open '%s'!\n", config.outfile);
          return CURLE_WRITE_ERROR;
        }
      }
      else {
        outs.filename = config.outfile;
        outs.stream = NULL; /* open when needed */
      }
    }
    if (config.infile) {
      /*
       * We have specified a file to upload
       */
      struct stat fileinfo;

      /* If no file name part is given in the URL, we add this file name */
      char *ptr=strstr(url, "://");
      if(ptr)
        ptr+=3;
      else
        ptr=url;
      ptr = strrchr(ptr, '/');
      if(!ptr || !strlen(++ptr)) {
        /* The URL has no file name part, add the local file name. In order to
           be able to do so, we have to create a new URL in another buffer.*/

        urlbuffer=(char *)malloc(strlen(url) + strlen(config.infile) + 3);
        if(!urlbuffer) {
          helpf("out of memory\n");
          return CURLE_OUT_OF_MEMORY;
        }
        if(ptr)
          /* there is a trailing slash on the URL */
          sprintf(urlbuffer, "%s%s", url, config.infile);
        else
          /* thers is no trailing slash on the URL */
          sprintf(urlbuffer, "%s/%s", url, config.infile);
        
        url = urlbuffer; /* use our new URL instead! */
      }

      infd=(FILE *) fopen(config.infile, "rb");
      if (!infd || stat(config.infile, &fileinfo)) {
        helpf("Can't open '%s'!\n", config.infile);
        return CURLE_READ_ERROR;
      }
      infilesize=fileinfo.st_size;
      
    }
    if((config.conf&CONF_UPLOAD) &&
       config.use_resume &&
       (0==config.resume_from)) {
      config.resume_from = -1; /* -1 will then force get-it-yourself */
    }
    if(config.headerfile) {
      /* open file for output: */
      if(strcmp(config.headerfile,"-")) {
        heads.filename = config.headerfile;
        headerfilep=NULL;
      }
      else
        headerfilep=stdout;
      heads.stream = headerfilep;
    }
    
    if(outs.stream && isatty(fileno(outs.stream)) &&
       !(config.conf&(CONF_UPLOAD|CONF_HTTPPOST)))
      /* we send the output to a tty and it isn't an upload operation,
         therefore we switch off the progress meter */
      config.conf |= CONF_NOPROGRESS;
    

    if (urlnum > 1) {
      fprintf(stderr, "\n[%d/%d]: %s --> %s\n",
              i+1, urlnum, url, config.outfile ? config.outfile : "<stdout>");
      if (separator) {
#ifdef CURL_SEPARATORS
        printf("%s%s\n", CURLseparator, url);
#endif
#ifdef MIME_SEPARATORS
        printf("--%s\n", MIMEseparator);
        printf("Content-ID: %s\n\n", url); 
#endif
      }
    }

    if(!config.errors)
      config.errors = stderr;

#ifdef WIN32
    if(!config.outfile && !(config.conf & CONF_GETTEXT)) {
      /* We get the output to stdout and we have not got the ASCII/text flag,
         then set stdout to be binary */
      setmode( 1, O_BINARY );
    }
#endif


    main_init();

    /* The new, v7-style easy-interface! */
    curl = curl_easy_init();
    if(curl) {
      curl_easy_setopt(curl, CURLOPT_FILE, (FILE *)&outs); /* where to store */
      /* what call to write: */
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_fwrite);
      curl_easy_setopt(curl, CURLOPT_INFILE, infd); /* for uploads */
      /* size of uploaded file: */
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, infilesize);
      curl_easy_setopt(curl, CURLOPT_URL, url);     /* what to fetch */
      curl_easy_setopt(curl, CURLOPT_PROXY, config.proxy); /* proxy to use */
      curl_easy_setopt(curl, CURLOPT_VERBOSE, config.conf&CONF_VERBOSE);
      curl_easy_setopt(curl, CURLOPT_HEADER, config.conf&CONF_HEADER);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, config.conf&CONF_NOPROGRESS);
      curl_easy_setopt(curl, CURLOPT_NOBODY, config.conf&CONF_NOBODY);
      curl_easy_setopt(curl, CURLOPT_FAILONERROR,
                       config.conf&CONF_FAILONERROR);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, config.conf&CONF_UPLOAD);
      curl_easy_setopt(curl, CURLOPT_POST, config.conf&CONF_POST);
      curl_easy_setopt(curl, CURLOPT_FTPLISTONLY,
                       config.conf&CONF_FTPLISTONLY);
      curl_easy_setopt(curl, CURLOPT_FTPAPPEND, config.conf&CONF_FTPAPPEND);
      curl_easy_setopt(curl, CURLOPT_NETRC, config.conf&CONF_NETRC);
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,
                       config.conf&CONF_FOLLOWLOCATION);
      curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, config.conf&CONF_GETTEXT);
      curl_easy_setopt(curl, CURLOPT_PUT, config.conf&CONF_PUT);
      curl_easy_setopt(curl, CURLOPT_MUTE, config.conf&CONF_MUTE);
      curl_easy_setopt(curl, CURLOPT_USERPWD, config.userpwd);
      curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, config.proxyuserpwd);
      curl_easy_setopt(curl, CURLOPT_RANGE, config.range);
      curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.timeout);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, config.postfields);
      
      /* new in libcurl 7.2: */
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, config.postfieldsize);

      curl_easy_setopt(curl, CURLOPT_REFERER, config.referer);
      curl_easy_setopt(curl, CURLOPT_AUTOREFERER,
                       config.conf&CONF_AUTO_REFERER);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, config.useragent);
      curl_easy_setopt(curl, CURLOPT_FTPPORT, config.ftpport);
      curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, config.low_speed_limit);
      curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, config.low_speed_time);
      curl_easy_setopt(curl, CURLOPT_RESUME_FROM,
                       config.use_resume?config.resume_from:0);
      curl_easy_setopt(curl, CURLOPT_COOKIE, config.cookie);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, config.headers);
      curl_easy_setopt(curl, CURLOPT_HTTPPOST, config.httppost);
      curl_easy_setopt(curl, CURLOPT_SSLCERT, config.cert);
      curl_easy_setopt(curl, CURLOPT_SSLCERTPASSWD, config.cert_passwd);
      curl_easy_setopt(curl, CURLOPT_CRLF, config.crlf);
      curl_easy_setopt(curl, CURLOPT_QUOTE, config.quote);
      curl_easy_setopt(curl, CURLOPT_POSTQUOTE, config.postquote);
      curl_easy_setopt(curl, CURLOPT_WRITEHEADER,
                       config.headerfile?&heads:NULL);
      curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config.cookiefile);
      curl_easy_setopt(curl, CURLOPT_SSLVERSION, config.ssl_version);
      curl_easy_setopt(curl, CURLOPT_TIMECONDITION, config.timecond);
      curl_easy_setopt(curl, CURLOPT_TIMEVALUE, config.condtime);
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, config.customrequest);
      curl_easy_setopt(curl, CURLOPT_STDERR, config.errors);
      
      /* three new ones in libcurl 7.3: */
      curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config.proxytunnel);
      curl_easy_setopt(curl, CURLOPT_INTERFACE, config.iface);
      curl_easy_setopt(curl, CURLOPT_KRB4LEVEL, config.krb4level);

      if((config.progressmode == CURL_PROGRESS_BAR) &&
         !(config.conf&(CONF_NOPROGRESS|CONF_MUTE))) {
        /* we want the alternative style, then we have to implement it
           ourselves! */
        progressbarinit(&progressbar);
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, myprogress);
        curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &progressbar);
      }

      res = curl_easy_perform(curl);

      if(config.writeout) {
        ourWriteOut(curl, config.writeout);
      }

      /* always cleanup */
      curl_easy_cleanup(curl);

      if((res!=CURLE_OK) && config.showerror)
        fprintf(config.errors, "curl: (%d) %s\n", res, errorbuffer);
    }
    else
      fprintf(config.errors, "curl: failed to init libcurl!\n");

    main_free();

    if((config.errors != stderr) &&
       (config.errors != stdout))
      /* it wasn't directed to stdout or stderr so close the file! */
      fclose(config.errors);
    
    if(config.headerfile && !headerfilep && heads.stream)
      fclose(heads.stream);

    if(urlbuffer)
      free(urlbuffer);
    if (config.outfile && outs.stream)
      fclose(outs.stream);
    if (config.infile)
      fclose(infd);
    if(headerfilep)
      fclose(headerfilep);
    
    if(url)
      free(url);

  }
#ifdef MIME_SEPARATORS
  if (separator)
    printf("--%s--\n", MIMEseparator);
#endif

  free_config_fields(&config);

  if(allocuseragent)
    free(config.useragent);

  /* cleanup memory used for URL globbing patterns */
  glob_cleanup(urls);

  return res;
}


int main(int argc, char *argv[])
{
  int res;
  memset(&config, 0, sizeof(struct Configurable));
  
  res = operate(argc, argv);
  free_config_fields(&config);

  return res;
}

static char *my_get_line(FILE *fp)
{
   char buf[4096];
   char *nl = NULL;
   char *retval = NULL;

   do
   {
      if (NULL == fgets(buf, sizeof(buf), fp))
         break;
      if (NULL == retval)
         retval = strdup(buf);
      else
      {
         if (NULL == (retval = realloc(retval,
                                       strlen(retval) + strlen(buf) + 1)))
            break;
         strcat(retval, buf);
      }
   }
   while (NULL == (nl = strchr(retval, '\n')));

   if (NULL != nl)
     *nl = '\0';

   return retval;
}
