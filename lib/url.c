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
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source: /cvsroot/curl/curl/lib/url.c,v $
 * $Revision: 1.15.2.4 $
 * $Date: 2000-05-08 22:35:45 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef HAVE_VPRINTF
#error "We can't compile without vprintf() support!"
#endif
#ifndef HAVE_SELECT
#error "We can't compile without select() support!"
#endif
#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#endif

#include "urldata.h"
#include <curl/curl.h>
#include "netrc.h"

#include "formdata.h"
#include "getenv.h"
#include "base64.h"
#include "ssluse.h"
#include "hostip.h"
#include "if2ip.h"
#include "download.h"
#include "sendf.h"
#include "speedcheck.h"
#include "getpass.h"
#include "progress.h"
#include "cookie.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "http.h"
#include "file.h"
#include "ldap.h"
#include "writeout.h"

#include "externaltypes.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* -- -- */

/***********************************************************************
 * Start with some silly functions to make win32-systems survive
 ***********************************************************************/
#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
static void win32_cleanup(void)
{
  WSACleanup();
}

static UrgError win32_init(void)
{
  WORD wVersionRequested;  
  WSADATA wsaData; 
  int err; 
  wVersionRequested = MAKEWORD(1, 1); 
    
  err = WSAStartup(wVersionRequested, &wsaData); 
    
  if (err != 0) 
    /* Tell the user that we couldn't find a useable */ 
    /* winsock.dll.     */ 
    return URG_FAILED_INIT; 
    
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
    return URG_FAILED_INIT; 
  }
  return URG_OK;
}
/* The Windows Sockets DLL is acceptable. Proceed. */ 
#else
static UrgError win32_init(void) { return URG_OK; }
#define win32_cleanup()
#endif


/*
 * This is the main global constructor for the lib. Call this before
 * _any_ libcurl usage. If this fails, *NO* libcurl functions may be
 * used, or havoc may be the result.
 */
UrgError curl_init(void)
{
  return win32_init();
}

/*
 * This is the main global destructor for the lib. Call this after
 * _all_ libcurl usage is done.
 */
void curl_free(void)
{
  win32_cleanup();
}

UrgError _urlget(struct UrlData *data);


void urlfree(struct UrlData *data, bool totally)
{
#ifdef USE_SSLEAY
  if (data->use_ssl) {
    if(data->ssl) {
      SSL_shutdown(data->ssl);
      SSL_set_connect_state(data->ssl);

      SSL_free (data->ssl);
      data->ssl = NULL;
    }
    if(data->ctx) {
      SSL_CTX_free (data->ctx);
      data->ctx = NULL;
    }
    data->use_ssl = FALSE; /* get back to ordinary socket usage */
  }
#endif /* USE_SSLEAY */

  /* close possibly still open sockets */
  if(-1 != data->secondarysocket) {
    sclose(data->secondarysocket);
    data->secondarysocket = -1;	
  }
  if(-1 != data->firstsocket) {
    sclose(data->firstsocket);
    data->firstsocket=-1;
  }


  if(data->ptr_proxyuserpwd) {
    free(data->ptr_proxyuserpwd);
    data->ptr_proxyuserpwd=NULL;
  }
  if(data->ptr_uagent) {
    free(data->ptr_uagent);
    data->ptr_uagent=NULL;
  }
  if(data->ptr_userpwd) {
    free(data->ptr_userpwd);
    data->ptr_userpwd=NULL;
  }
  if(data->ptr_rangeline) {
    free(data->ptr_rangeline);
    data->ptr_rangeline=NULL;
  }
  if(data->ptr_ref) {
    free(data->ptr_ref);
    data->ptr_ref=NULL;
  }
  if(data->ptr_cookie) {
    free(data->ptr_cookie);
    data->ptr_cookie=NULL;
  }
  if(data->ptr_host) {
    free(data->ptr_host);
    data->ptr_host=NULL;
  }

  if(totally) {
    /* we let the switch decide whether we're doing a part or total
       cleanup */

    /* check for allocated [URL] memory to free: */
    if(data->freethis)
      free(data->freethis);

    if(data->headerbuff)
      free(data->headerbuff);

    cookie_cleanup(data->cookies);

    free(data);

    /* global cleanup */
    curl_free();
  }
}

UrgError curl_open(CURL **curl, char *url)
{
  /* We don't yet support specifying the URL at this point */
  struct UrlData *data;

  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = (struct UrlData *)malloc(sizeof(struct UrlData));
  if(data) {
    memset(data, 0, sizeof(struct UrlData));
    data->handle = STRUCT_OPEN;

    /* We do some initial setup here, all those fields that can't be just 0 */

    data-> headerbuff=(char*)malloc(HEADERSIZE);
    if(!data->headerbuff) {
      free(data); /* free the memory again */
      return URG_OUT_OF_MEMORY;
    }

    data-> headersize=HEADERSIZE;

#if 0
    /* Let's set some default values: */
    curl_setopt(data, URGTAG_FILE, stdout); /* default output to stdout */
    curl_setopt(data, URGTAG_INFILE, stdin);  /* default input from stdin */
    curl_setopt(data, URGTAG_STDERR, stderr);  /* default stderr to stderr! */
#endif

    data->out = stdout; /* default output to stdout */
    data->in  = stdin;  /* default input from stdin */
    data->err  = stderr;  /* default stderr to stderr */

    data->firstsocket = -1; /* no file descriptor */
    data->secondarysocket = -1; /* no file descriptor */

    /* use fwrite as default function to store output */
    data->fwrite = (size_t (*)(char *, size_t, size_t, FILE *))fwrite;

    /* use fread as default function to read input */
    data->fread = (size_t (*)(char *, size_t, size_t, FILE *))fread;

    data->infilesize = -1; /* we don't know any size */

    data->current_speed = -1; /* init to negative == impossible */

    *curl = data;
    return URG_OK;
  }

  /* this is a very serious error */
  return URG_OUT_OF_MEMORY;
}

static UrgError
conf_to_internal(struct UrlData *data, long conf)
{
  unsigned long bit;
  unsigned long mask;
  bool onoff;
  
  for(bit=0; bit<32; bit++) {
    mask = (unsigned long)1 << bit;
    onoff = (conf & mask)?TRUE:FALSE; /* converted to true/false */
    switch(mask) {
    case CONF_PROXY:
      data->bits.httpproxy = onoff;
      break;
    case CONF_PORT:
      data->bits.set_port = onoff;
      break;
    case CONF_VERBOSE:
      data->bits.verbose = onoff;
      break;
    case CONF_HEADER:
      data->bits.http_include_header = onoff;
      break;
    case CONF_USERPWD:
      data->bits.user_passwd = onoff;
      break;
    case CONF_NOPROGRESS:
      data->bits.hide_progress = onoff;
      break;
    case CONF_NOBODY:
      data->bits.no_body = onoff;
      break;
    case CONF_FAILONERROR:
      data->bits.http_fail_on_error = onoff;
      break;
    case CONF_RANGE:
      data->bits.set_range = onoff;
      break;
    case CONF_UPLOAD:
      data->bits.upload = onoff;
      break;
    case CONF_POST:
      data->bits.http_post = onoff;
      break;
    case CONF_FTPLISTONLY:
      data->bits.ftp_list_only = onoff;
      break;
    case CONF_REFERER:
      data->bits.http_set_referer = onoff;
      break;
    case CONF_PROXYUSERPWD:
      data->bits.proxy_user_passwd = onoff;
      break;
    case CONF_FTPPORT:
      data->bits.ftp_use_port = onoff;
      break;
    case CONF_FTPAPPEND:
      data->bits.ftp_append = onoff;
      break;
    case CONF_NETRC:
      data->bits.use_netrc = onoff;
      break;
    case CONF_FOLLOWLOCATION:
      data->bits.http_follow_location = onoff;
      break;
    case CONF_FTPASCII:
      data->bits.ftp_ascii = onoff;
      break;
    case CONF_HTTPPOST:
      data->bits.http_formpost = onoff;
      break;
    case CONF_PUT:
      data->bits.http_put = onoff;
      break;
    case CONF_MUTE:
      data->bits.mute = onoff;
      break;
#if 0
      /* these defines don't exist anymore */
    case CONF_DICT:
    case CONF_FILE:
    case CONF_LDAP:
    case CONF_HTTP:
    case CONF_HTTPS:
    case CONF_GOPHER:
    case CONF_FTP:
    case CONF_TELNET:
    case CONF_NOPROT:
#endif
    default:
      /* not a supported user-flag */
      break;
    }
  }
  return URG_OK;
}


UrgError curl_setopt(CURL *curl, CURLoption option, ...)
{
  struct UrlData *data = curl;
  va_list param;
  char *cookiefile;

  va_start(param, option);

  switch(option) {
  case URGTAG_TIMECONDITION:
    data->timecondition = va_arg(param, long);
    break;

  case URGTAG_TIMEVALUE:
    data->timevalue = va_arg(param, long);
    break;

  case URGTAG_SSLVERSION:
    data->ssl_version = va_arg(param, long);
    break;

  case URGTAG_COOKIEFILE:
    cookiefile = (char *)va_arg(param, void *);
    if(cookiefile) {
      data->cookies = cookie_init(cookiefile);
    }
    break;
  case URGTAG_WRITEHEADER:
    data->writeheader = (FILE *)va_arg(param, FILE *);
    break;
  case URGTAG_COOKIE:
    data->cookie = va_arg(param, char *);
    break;
  case URGTAG_ERRORBUFFER:
    data->errorbuffer = va_arg(param, char *);
    break;
  case URGTAG_FILE:
    data->out = va_arg(param, FILE *);
    break;
  case URGTAG_FTPPORT:
    data->ftpport = va_arg(param, char *);
    break;
  case URGTAG_HTTPHEADER:
    data->headers = va_arg(param, struct HttpHeader *);
    break;
  case URGTAG_CUSTOMREQUEST:
    data->customrequest = va_arg(param, char *);
    break;
  case URGTAG_HTTPPOST:
    data->httppost = va_arg(param, struct HttpPost *);
    break;
  case URGTAG_INFILE:
    data->in = va_arg(param, FILE *);
    break;
  case URGTAG_INFILESIZE:
    data->infilesize = va_arg(param, long);
    break;
  case URGTAG_LOW_SPEED_LIMIT:
    data->low_speed_limit=va_arg(param, long);
    break;
  case URGTAG_LOW_SPEED_TIME:
    data->low_speed_time=va_arg(param, long);
    break;
  case URGTAG_URL:
    data->url = va_arg(param, char *);
    break;
  case URGTAG_PORT:
    /* this typecast is used to fool the compiler to NOT warn for a
       "cast from pointer to integer of different size" */
    data->port = (unsigned short)(va_arg(param, long));
    break;
  case URGTAG_POSTFIELDS:
    data->postfields = va_arg(param, char *);
    break;
  case URGTAG_PROGRESSMODE:
    data->progress.mode = va_arg(param, long);
    break;
  case URGTAG_REFERER:
    data->referer = va_arg(param, char *);
    break;
  case URGTAG_PROXY:
    data->proxy = va_arg(param, char *);
    break;
  case URGTAG_FLAGS:
    conf_to_internal(data, va_arg(param, long));
    break;
  case URGTAG_TIMEOUT:
    data->timeout = va_arg(param, long);
    break;
  case URGTAG_USERAGENT:
    data->useragent = va_arg(param, char *);
    break;
  case URGTAG_USERPWD:
    data->userpwd = va_arg(param, char *);
    break;
  case URGTAG_POSTQUOTE:
    data->postquote = va_arg(param, struct curl_slist *);
    break;
  case URGTAG_PROXYUSERPWD:
    data->proxyuserpwd = va_arg(param, char *);
    break;
  case URGTAG_RANGE:
    data->range = va_arg(param, char *);
    break;
  case URGTAG_RESUME_FROM:
    data->resume_from = va_arg(param, long);
    break;
  case URGTAG_STDERR:
    data->err = va_arg(param, FILE *);
    break;
  case URGTAG_WRITEFUNCTION:
    data->fwrite = va_arg(param, void *);
    break;
  case URGTAG_WRITEINFO:
    data->writeinfo = va_arg(param, char *);
    break;
  case URGTAG_READFUNCTION:
    data->fread = va_arg(param, void *);
    break;
  case URGTAG_SSLCERT:
    data->cert = va_arg(param, char *);
    break;
  case URGTAG_SSLCERTPASSWD:
    data->cert_passwd = va_arg(param, char *);
    break;
  case URGTAG_CRLF:
    data->crlf = va_arg(param, long);
    break;
  case URGTAG_QUOTE:
    data->quote = va_arg(param, struct curl_slist *);
    break;
  default:
    /* unknown tag and its companion, just ignore: */
    return URG_READ_ERROR; /* correct this */
  }
  return URG_OK;
}


/*
 * Read everything until a newline.
 */

int GetLine(int sockfd, char *buf, struct UrlData *data)
{
  int nread;
  int read_rc=1;
  char *ptr;
  ptr=buf;

  /* get us a full line, terminated with a newline */
  for(nread=0;
      (nread<BUFSIZE) && read_rc;
      nread++, ptr++) {
#ifdef USE_SSLEAY
    if (data->use_ssl) {
      read_rc = SSL_read(data->ssl, ptr, 1);
    }
    else {
#endif
      read_rc = sread(sockfd, ptr, 1);
#ifdef USE_SSLEAY
    }
#endif /* USE_SSLEAY */
    if (*ptr == '\n')
      break;
  }
  *ptr=0; /* zero terminate */

  if(data->bits.verbose) {
    fputs("< ", data->err);
    fwrite(buf, 1, nread, data->err);
    fputs("\n", data->err);
  }
  return nread;
}


#ifndef WIN32
#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
RETSIGTYPE alarmfunc(int signal)
{
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void)signal;
  return;
}
#endif

UrgError curl_write(CURLconnect *c_conn, char *buf, size_t amount,
                   size_t *n)
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  struct UrlData *data;
  size_t bytes_written;

  if(!n || !conn || (conn->handle != STRUCT_CONNECT))
    return URG_FAILED_INIT;
  data = conn->data;

#ifdef USE_SSLEAY
  if (data->use_ssl) {
    bytes_written = SSL_write(data->ssl, buf, amount);
  }
  else {
#endif
    bytes_written = swrite(conn->writesockfd, buf, amount);
#ifdef USE_SSLEAY
  }
#endif /* USE_SSLEAY */

  *n = bytes_written;
  return URG_OK;
}

UrgError curl_read(CURLconnect *c_conn, char *buf, size_t buffersize,
                   size_t *n)
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  struct UrlData *data;
  size_t nread;

  if(!n || !conn || (conn->handle != STRUCT_CONNECT))
    return URG_FAILED_INIT;
  data = conn->data;

#ifdef USE_SSLEAY
  if (data->use_ssl) {
    nread = SSL_read (data->ssl, buf, buffersize);
  }
  else {
#endif
    nread = sread (conn->sockfd, buf, buffersize);
#ifdef USE_SSLEAY
  }
#endif /* USE_SSLEAY */
  *n = nread;
  return URG_OK;
}

UrgError curl_disconnect(CURLconnect *c_connect)
{
  return URG_OK;
}

/*
 * NAME curl_connect()
 *
 * DESCRIPTION
 *
 * Connects to the peer server and performs the initial setup. This function
 * writes a connect handle to its second argument that is a unique handle for
 * this connect. This allows multiple connects from the same handle returned
 * by curl_open().
 *
 * EXAMPLE
 *
 * CURLCode result;
 * CURL curl;
 * CURLconnect connect;
 * result = curl_connect(curl, &connect);
 */

UrgError curl_connect(CURL *curl, CURLconnect **in_connect)
{
  char *tmp;
  char *buf;
  UrgError result;
  char resumerange[12]="";
  struct UrlData *data = curl;
  struct connectdata *conn;

  if(!data || (data->handle != STRUCT_OPEN))
    return URG_FAILED_INIT; /* TBD: make error codes */

  if(!data->url)
    return URG_FAILED_INIT; /* TBD: missing URL error code */

  conn = (struct connectdata *)malloc(sizeof(struct connectdata));
  if(!conn) {
    *in_connect = NULL; /* clear the pointer */
    return URG_OUT_OF_MEMORY;
  }
  *in_connect = conn;

  memset(conn, 0, sizeof(struct connectdata));
  conn->handle = STRUCT_CONNECT;

  conn->data = data; /* remember our daddy */
  conn->state = CONN_INIT;

  strcpy(conn->gname, "default.com");
  strcpy(conn->path, "/");

  buf = data->buffer; /* this is our buffer */

#if 0
  signal(SIGALRM, alarmfunc);
#endif

  /* Parse <url> */
  /* We need to parse the url, even when using the proxy, because
   * we will need the hostname and port in case we are trying
   * to SSL connect through the proxy -- and we don't know if we
   * will need to use SSL until we parse the url ...
   */
  if((2 == sscanf(data->url, "%64[^:]://%" URL_MAX_LENGTH_TXT "[^\n]",
                  conn->proto,
                  conn->path)) && strequal(conn->proto, "file")) {
    /* we deal with file://<host>/<path> differently since it
       supports no hostname other than "localhost" and "127.0.0.1",
       which is unique among the protocols specified in RFC 1738 */
    if (strnequal(conn->path, "localhost/", 10) ||
        strnequal(conn->path, "127.0.0.1/", 10))
      /* ... since coincidentally both host strings are of equal length
         otherwise, <host>/ is quietly ommitted */
      strcpy(conn->path, &conn->path[10]);

    strcpy(conn->proto, "file");
  }
  else if (2 > sscanf(data->url, "%64[^\n:]://%256[^\n/]%" URL_MAX_LENGTH_TXT "[^\n]",
                 conn->proto, conn->gname, conn->path)) {
    
      
    /* badly formatted, let's try the browser-style _without_ 'http://' */
    if((1 > sscanf(data->url, "%256[^\n/]%" URL_MAX_LENGTH_TXT "[^\n]",
                   conn->gname, conn->path)) ) {
      failf(data, "<url> malformed");
      return URG_URL_MALFORMAT;
    }
    if(strnequal(conn->gname, "FTP", 3)) {
      strcpy(conn->proto, "ftp");
    }
    else if(strnequal(conn->gname, "GOPHER", 6))
      strcpy(conn->proto, "gopher");
#ifdef USE_SSLEAY
    else if(strnequal(conn->gname, "HTTPS", 5))
      strcpy(conn->proto, "https");
#endif /* USE_SSLEAY */
    else if(strnequal(conn->gname, "TELNET", 6))
      strcpy(conn->proto, "telnet");
    else if (strnequal(conn->gname, "DICT", sizeof("DICT")-1))
      strcpy(conn->proto, "DICT");
    else if (strnequal(conn->gname, "LDAP", sizeof("LDAP")-1))
      strcpy(conn->proto, "LDAP");
    else {
      strcpy(conn->proto, "http");
    }

    conn->protocol |= PROT_MISSING; /* not given in URL */
  }


  if(data->bits.user_passwd && !data->bits.use_netrc) {
    if(':' != *data->userpwd) {
      if((1 <= sscanf(data->userpwd, "%127[^:]:%127s",
                      data->user, data->passwd))) {
        /* check for password, if no ask for one */
        if( !data->passwd[0] )
        {
          strncpy(data->passwd, getpass("password: "), sizeof(data->passwd));
        }
      }
    }
    if(!data->user[0]) {
      failf(data, "USER malformat: user name can't be zero length");
      return URG_MALFORMAT_USER;
    }
  }

  if(data->bits.proxy_user_passwd) {
    if(':' != *data->proxyuserpwd) {
      if((1 <= sscanf(data->proxyuserpwd, "%127[^:]:%127s",
                      data->proxyuser, data->proxypasswd))) {
        /* check for password, if no ask for one */
        if( !data->proxypasswd[0] )
        {
          strncpy(data->proxypasswd, getpass("proxy password: "), sizeof(data->proxypasswd));
        }
      }
    }
    if(!data->proxyuser[0]) {
      failf(data, " Proxy USER malformat: user name can't be zero length");
      return URG_MALFORMAT_USER;
    }
  }

  conn->name = conn->gname;
  conn->ppath = conn->path;
  data->hostname = conn->name;


  if(!data->bits.httpproxy) {
    /* If proxy was not specified, we check for default proxy environment
       variables, to enable i.e Lynx compliance:

       HTTP_PROXY http://some.server.dom:port/
       HTTPS_PROXY http://some.server.dom:port/
       FTP_PROXY http://some.server.dom:port/
       GOPHER_PROXY http://some.server.dom:port/
       NO_PROXY host.domain.dom  (a comma-separated list of hosts which should
       not be proxied, or an asterisk to override all proxy variables)
       ALL_PROXY seems to exist for the CERN www lib. Probably the first to
       check for.
 
       */
    char *no_proxy=GetEnv("NO_PROXY");
    char *proxy=NULL;
    char proxy_env[128];

    if(!no_proxy || !strequal("*", no_proxy)) {
      /* NO_PROXY wasn't specified or it wasn't just an asterisk */
      char *nope;

      nope=no_proxy?strtok(no_proxy, ", "):NULL;
      while(nope) {
        if(strlen(nope) <= strlen(conn->name)) {
          char *checkn=
            conn->name + strlen(conn->name) - strlen(nope);
          if(strnequal(nope, checkn, strlen(nope))) {
            /* no proxy for this host! */
            break;
          }
        }
	nope=strtok(NULL, ", ");
      }
      if(!nope) {
	/* It was not listed as without proxy */
	char *protop = conn->proto;
	char *envp = proxy_env;
	char *prox;

	/* Now, build <PROTOCOL>_PROXY and check for such a one to use */
	while(*protop) {
	  *envp++ = toupper(*protop++);
	}
	/* append _PROXY */
	strcpy(envp, "_PROXY");
#if 0
	infof(data, "DEBUG: checks the environment variable %s\n", proxy_env);
#endif
	/* read the protocol proxy: */
	prox=GetEnv(proxy_env);

	if(prox && *prox) { /* don't count "" strings */
	  proxy = prox; /* use this */
        }
        else
          proxy = GetEnv("ALL_PROXY"); /* default proxy to use */

        if(proxy && *proxy) {
          /* we have a proxy here to set */
          data->proxy = proxy;
          data->bits.httpproxy=1;
        }
      } /* if (!nope) - it wasn't specfied non-proxy */
    } /* NO_PROXY wasn't specified or '*' */
  } /* if not using proxy */

  if((conn->protocol&PROT_MISSING) && data->bits.httpproxy ) {
    /* We're guessing prefixes here and since we're told to use a proxy, we
       need to add the protocol prefix to the URL string before we continue!
       */
    char *reurl;

    reurl = maprintf("%s://%s", conn->proto, data->url);

    if(!reurl)
      return URG_OUT_OF_MEMORY;

    data->url = reurl;
    if(data->freethis)
      free(data->freethis);
    data->freethis = reurl;

    conn->protocol &= ~PROT_MISSING; /* switch that one off again */
  }

  /* RESUME on a HTTP page is a tricky business. First, let's just check that
     'range' isn't used, then set the range parameter and leave the resume as
     it is to inform about this situation for later use. We will then
     "attempt" to resume, and if we're talking to a HTTP/1.1 (or later)
     server, we will get the document resumed. If we talk to a HTTP/1.0
     server, we just fail since we can't rewind the file writing from within
     this function. */
  if(data->resume_from) {
    if(!data->bits.set_range) {
      /* if it already was in use, we just skip this */
      sprintf(resumerange, "%d-", data->resume_from);
      data->range=resumerange; /* tell ourselves to fetch this range */
      data->bits.set_range = 1; /* switch on range usage */
    }
  }


  if(data->timeout) {
    /* We set the timeout on the connection/resolving phase first, separately
       from the download/upload part to allow a maximum time on everything */
    myalarm(data->timeout); /* this sends a signal when the timeout fires
			       off, and that will abort system calls */
  }

  /*
   * Hmm, if we are using a proxy, then we can skip the GOPHER and the
   * FTP steps, although we cannot skip the HTTPS step (since the proxy
   * works differently, depending on whether its SSL or not).
   */

  if (strequal(conn->proto, "HTTP")) {
    if(!data->port)
      data->port = PORT_HTTP;
    data->remote_port = PORT_HTTP;
    conn->protocol |= PROT_HTTP;
    data->curl_do = http;
    data->curl_done = http_done;
  }
  else if (strequal(conn->proto, "HTTPS")) {
#ifdef USE_SSLEAY
    if(!data->port)
      data->port = PORT_HTTPS;
    data->remote_port = PORT_HTTPS;
    conn->protocol |= PROT_HTTP;
    conn->protocol |= PROT_HTTPS;

    data->curl_do = http;
    data->curl_done = http_done;
    data->curl_connect = http_connect;

#else /* USE_SSLEAY */
    failf(data, "SSL is disabled, https: not supported!");
    return URG_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSLEAY */
  }
  else if (strequal(conn->proto, "GOPHER")) {
    if(!data->port)
      data->port = PORT_GOPHER;
    data->remote_port = PORT_GOPHER;
    /* Skip /<item-type>/ in path if present */
    if (isdigit((int)conn->path[1])) {
      conn->ppath = strchr(&conn->path[1], '/');
      if (conn->ppath == NULL)
	conn->ppath = conn->path;
      }
    conn->protocol |= PROT_GOPHER;
    data->curl_do = http;
    data->curl_done = http_done;
  }
  else if(strequal(conn->proto, "FTP")) {
    char *type;
    if(!data->port)
      data->port = PORT_FTP;
    data->remote_port = PORT_FTP;
    conn->protocol |= PROT_FTP;

    if(data->bits.httpproxy) {
      data->curl_do = http;
      data->curl_done = http_done;
    }
    else {
      data->curl_do = ftp;
      data->curl_done = ftp_done;

      data->curl_connect = ftp_connect;
    }

    conn->ppath++; /* don't include the initial slash */

    /* FTP URLs support an extension like ";type=<typecode>" that
       we'll try to get now! */
    type=strstr(conn->ppath, ";type=");
    if(!type) {
      type=strstr(conn->gname, ";type=");
    }
    if(type) {
      char command;
      *type=0;
      command = toupper(type[6]);
      switch(command) {
      case 'A': /* ASCII mode */
	data->bits.ftp_ascii = 1;
	break;
      case 'D': /* directory mode */
	data->bits.ftp_list_only = 1;
	break;
      case 'I': /* binary mode */
      default:
	/* switch off ASCII */
	data->bits.ftp_ascii = 0;
	break;
      }
    }
  }
  else if(strequal(conn->proto, "TELNET")) {
    /* telnet testing factory */
    conn->protocol |= PROT_TELNET;
    if(!data->port)
      data->port = PORT_TELNET;
    data->remote_port = PORT_TELNET;

    data->curl_do = telnet;
    data->curl_done = telnet_done;

  }
  else if (strequal(conn->proto, "DICT")) {
    conn->protocol |= PROT_DICT;
    if(!data->port)
      data->port = PORT_DICT;
    data->remote_port = PORT_DICT;
    data->curl_do = dict;
    data->curl_done = dict_done;
  }
  else if (strequal(conn->proto, "LDAP")) {
    conn->protocol |= PROT_LDAP;
    if(!data->port)
      data->port = PORT_LDAP;
    data->remote_port = PORT_LDAP;
    data->curl_do = ldap;
    data->curl_done = ldap_done;
  }
  else if (strequal(conn->proto, "FILE")) {
    conn->protocol |= PROT_FILE;

    data->curl_do = file;
    /* no done() function */
  }

  else {
    failf(data, "Unsupported protocol: %s", conn->proto);
    return URG_UNSUPPORTED_PROTOCOL;
  }

  if(data->bits.use_netrc) {
    if(ParseNetrc(data->hostname, data->user, data->passwd)) {
      infof(data, "Couldn't find host %s in the .netrc file, using defaults",
            data->hostname);
    }
    /* weather we failed or not, we don't know which fields that were filled
       in anyway */
    if(!data->user[0])
      strcpy(data->user, CURL_DEFAULT_USER);
    if(!data->passwd[0])
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
    if(conn->protocol&PROT_HTTP) {
      data->bits.user_passwd = 1; /* enable user+password */
    }
  }
  else if(!(data->bits.user_passwd) &&
	  (conn->protocol & (PROT_FTP|PROT_HTTP)) ) {
    /* This is a FTP or HTTP URL, and we haven't got the user+password in
       the extra parameter, we will now try to extract the possible
       user+password pair in a string like:
       ftp://user:password@ftp.my.site:8021/README */
    char *ptr=NULL; /* assign to remove possible warnings */
    if(':' == *conn->name) {
      failf(data, "URL malformat: user can't be zero length");
      return URG_URL_MALFORMAT_USER;
    }
    if((1 <= sscanf(conn->name, "%127[^:]:%127[^@]",
		    data->user, data->passwd)) &&
       (ptr=strchr(conn->name, '@'))) {
      conn->name = ++ptr;
      data->bits.user_passwd=1; /* enable user+password */
    }
    else {
      strcpy(data->user, CURL_DEFAULT_USER);
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
    }
  }

  if(!data->bits.httpproxy) {
    /* If not connecting via a proxy, extract the port from the URL, if it is
     * there, thus overriding any defaults that might have been set above. */
    tmp = strchr(conn->name, ':');
    if (tmp) {
      *tmp++ = '\0';
      data->port = atoi(tmp);
    }
    
    /* Connect to target host right on */
    if(!(conn->hp = GetHost(data, conn->name))) {
      failf(data, "Couldn't resolv host '%s'", conn->name);
      return URG_COULDNT_RESOLVE_HOST;
    }
  }
  else {
    char *prox_portno;
    char *endofprot;

    /* We need to make a duplicate of the proxy so that we can modify the
       string safely. */
    char *proxydup=strdup(data->proxy);

    /* We use 'proxyptr' to point to the proxy name from now on... */
    char *proxyptr=proxydup;

    if(NULL == proxydup) {
      failf(data, "memory shortage");
      return URG_OUT_OF_MEMORY;
    }

    /* we use proxy all right, but we wanna know the remote port for SSL
       reasons */
    tmp = strchr(conn->name, ':');
    if (tmp) {
      *tmp++ = '\0'; /* cut off the name there */
      data->remote_port = atoi(tmp);
    }

    /* Daniel Dec 10, 1998:
       We do the proxy host string parsing here. We want the host name and the
       port name. Accept a protocol:// prefix, even though it should just be
       ignored. */

    /* 1. skip the protocol part if present */
    endofprot=strstr(proxyptr, "://");
    if(endofprot) {
      proxyptr = endofprot+3;
    }

    /* allow user to specify proxy.server.com:1080 if desired */
    prox_portno = strchr (proxyptr, ':');
    if (prox_portno) {
      *prox_portno = 0x0; /* cut off number from host name */
      prox_portno ++;
      /* now set the local port number */
      data->port = atoi(prox_portno);
    }

    /* connect to proxy */
    if(!(conn->hp = GetHost(data, proxyptr))) {
      failf(data, "Couldn't resolv proxy '%s'", proxyptr);
      return URG_COULDNT_RESOLVE_PROXY;
    }

    free(proxydup); /* free the duplicate pointer and not the modified */
  }
  pgrsTime(data, TIMER_NAMELOOKUP);

  data->firstsocket = socket(AF_INET, SOCK_STREAM, 0);

  memset((char *) &conn->serv_addr, '\0', sizeof(conn->serv_addr));
  memcpy((char *)&(conn->serv_addr.sin_addr),
         conn->hp->h_addr, conn->hp->h_length);
  conn->serv_addr.sin_family = conn->hp->h_addrtype;
  conn->serv_addr.sin_port = htons(data->port);

  if (connect(data->firstsocket,
              (struct sockaddr *) &(conn->serv_addr),
              sizeof(conn->serv_addr)
              ) < 0) {
    switch(errno) {
#ifdef ECONNREFUSED
      /* this should be made nicer */
    case ECONNREFUSED:
      failf(data, "Connection refused");
      break;
#endif
#ifdef EINTR
    case EINTR:
      failf(data, "Connection timeouted");
      break;
#endif
    default:
      failf(data, "Can't connect to server: %d", errno);
      break;
    }
    return URG_COULDNT_CONNECT;
  }

  if(data->bits.proxy_user_passwd) {
    char authorization[512];
    sprintf(data->buffer, "%s:%s", data->proxyuser, data->proxypasswd);
    base64Encode(data->buffer, authorization);

    data->ptr_proxyuserpwd = maprintf("Proxy-authorization: Basic %s\015\012",
				      authorization);
  }
  if((conn->protocol&PROT_HTTP) || data->bits.httpproxy) {
    if(data->useragent) {
      data->ptr_uagent = maprintf("User-Agent: %s\015\012", data->useragent);
    }
  }

  if(data->curl_connect) {
    /* is there a post-connect() procedure? */
    result = data->curl_connect(conn);
  }

  pgrsTime(data, TIMER_CONNECT);

  conn->now = tvnow(); /* time this *after* the connect is done */
  conn->bytecount = 0;
  
  /* Figure out the ip-number and the first host name it shows: */
  {
    struct in_addr in;
    (void) memcpy(&in.s_addr, *conn->hp->h_addr_list, sizeof (in.s_addr));
    infof(data, "Connected to %s (%s)\n", conn->hp->h_name, inet_ntoa(in));
  }

#if 0 /* Kerberos experiements! Beware! Take cover! */
  kerberos_connect(data, name);
#endif

#ifdef __EMX__
  /* 20000330 mgs
   * the check is quite a hack...
   * we're calling _fsetmode to fix the problem with fwrite converting newline
   * characters (you get mangled text files, and corrupted binary files when
   * you download to stdout and redirect it to a file). */

  if ((data->out)->_handle == NULL) {
    _fsetmode(stdout, "b");
  }
#endif

  return URG_OK;
}

UrgError curl_done(CURLconnect *c_connect)
{
  struct connectdata *conn = c_connect;
  struct UrlData *data;
  UrgError result;

  if(!conn || (conn->handle!= STRUCT_CONNECT)) {
    return URG_FAILED_INIT; /* TBD: make a proper return code */
  }
  if(conn->state != CONN_DO) {
    /* This can only be called after a curl_do() */
    return URG_FAILED_INIT; /* TBD: make a proper return code */
  }
  data = conn->data;

  /* this calls the protocol-specific function pointer previously set */
  if(data->curl_done)
    result = data->curl_done(conn);
  else
    result = URG_OK;

  pgrsDone(data); /* done with the operation */

  conn->state = CONN_DONE;

  return result;
}

UrgError curl_do(CURLconnect *in_conn)
{
  struct connectdata *conn = in_conn;
  struct UrlData *data = conn->data;
  UrgError result;

  if(!conn || (conn->handle!= STRUCT_CONNECT)) {
    return URG_FAILED_INIT; /* TBD: make a proper return code */
  }
  if(conn->state != CONN_INIT) {
    return URG_FAILED_INIT; /* TBD: make a proper return code */
  }

  if(data->curl_do) {
    /* generic protocol-specific function pointer set in curl_connect() */
    result = data->curl_do(conn);
    if(result) {
      conn->state = CONN_ERROR;
      return result;
    }
  }

  conn->state = CONN_DO; /* we have entered this state */

#if 0
  if(conn->bytecount) {
    double ittook = tvdiff (tvnow(), conn->now);
    infof(data, "%i bytes transfered in %.3lf seconds (%.0lf bytes/sec).\n",
          conn->bytecount, ittook, (double)conn->bytecount/(ittook!=0.0?ittook:1));
  }
#endif
  return URG_OK;
}

