#ifndef __URLDATA_H
#define __URLDATA_H
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
 * $Source: /cvsroot/curl/curl/lib/urldata.h,v $
 * $Revision: 1.31 $
 * $Date: 2000-11-13 18:23:21 $
 * $Author: bagder $
 * $State: Exp $
 * $Locker:  $
 *
 * ------------------------------------------------------------
 ****************************************************************************/

/* This file is for lib internal stuff */

#include "setup.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#define PORT_FTP 21
#define PORT_TELNET 23
#define PORT_GOPHER 70
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_DICT 2628
#define PORT_LDAP 389

#define DICT_MATCH "/MATCH:"
#define DICT_MATCH2 "/M:"
#define DICT_MATCH3 "/FIND:"
#define DICT_DEFINE "/DEFINE:"
#define DICT_DEFINE2 "/D:"
#define DICT_DEFINE3 "/LOOKUP:"

#define CURL_DEFAULT_USER "anonymous"
#define CURL_DEFAULT_PASSWORD "curl_by_daniel@haxx.se"

#include "cookie.h"
#include "formdata.h"
    
#ifdef USE_SSLEAY
/* SSLeay stuff usually in /usr/local/ssl/include */
#ifdef USE_OPENSSL
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#else
#include "rsa.h"
#include "crypto.h"
#include "x509.h"
#include "pem.h"
#include "ssl.h"
#include "err.h"
#endif
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "timeval.h"

#include <curl/curl.h>

/* Download buffer size, keep it fairly big for speed reasons */
#define BUFSIZE (1024*50)

/* Upload buffer size, keep it smallish to get faster progress meter
   updates. This should probably become dynamic and adjust to the upload
   speed. */
#define UPLOAD_BUFSIZE (1024*2)

/* Initial size of the buffer to store headers in, it'll be enlarged in case
   of need. */
#define HEADERSIZE 256

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

typedef enum {
  STRUCT_NONE,
  STRUCT_OPEN,
  STRUCT_CONNECT,
  STRUCT_LAST
} Handle;

typedef enum {
  CONN_NONE,  /* illegal state */
  CONN_INIT,  /* curl_connect() has been called */
  CONN_DO,    /* curl_do() has been called successfully */
  CONN_DONE,  /* curl_done() has been called successfully */
  CONN_ERROR, /* and error has occurred */
  CONN_LAST   /* illegal state */
} ConnState;

#ifdef KRB4
struct krb4buffer {
  void *data;
  size_t size;
  size_t index;
  int eof_flag;
};
enum protection_level { 
    prot_clear, 
    prot_safe, 
    prot_confidential, 
    prot_private 
};
#endif

/*
 * The connectdata struct contains all fields and variables that should be
 * unique for an entire connection.
 */
struct connectdata {
  /**** Fields set when inited and not modified again */

  /* To better see what kind of struct that is passed as input, *ALL* publicly
     returned handles MUST have this initial 'Handle'. */
  Handle handle; /* struct identifier */
  struct UrlData *data; /* link to the root CURL struct */

  /**** curl_connect() phase fields */
  ConnState state; /* for state dependent actions */

  long protocol; /* PROT_* flags concerning the protocol set */
#define PROT_MISSING (1<<0)
#define PROT_GOPHER  (1<<1)
#define PROT_HTTP    (1<<2)
#define PROT_HTTPS   (1<<3)
#define PROT_FTP     (1<<4)
#define PROT_TELNET  (1<<5)
#define PROT_DICT    (1<<6)
#define PROT_LDAP    (1<<7)
#define PROT_FILE    (1<<8)

  char *hostent_buf; /* pointer to allocated memory for name info */
  struct hostent *hp;
  struct sockaddr_in serv_addr;
  char proto[64];
  char gname[256];
  char *name;
  char path[URL_MAX_LENGTH];
  char *ppath;
  long bytecount;
  struct timeval now;

  long upload_bufsize; /* adjust as you see fit, never bigger than BUFSIZE
                          never smaller than UPLOAD_BUFSIZE */

  /* These two functions MUST be set by the curl_connect() function to be
     be protocol dependent */
  CURLcode (*curl_do)(struct connectdata *connect);
  CURLcode (*curl_done)(struct connectdata *connect);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * after the connect() and everything is done, as a step in the connection.
   */ 
  CURLcode (*curl_connect)(struct connectdata *connect);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * in the curl_close() function if protocol-specific cleanups are required.
   */ 
  CURLcode (*curl_close)(struct connectdata *connect);

  /**** curl_get() phase fields */

  /* READ stuff */
  int sockfd;		 /* socket to read from or -1 */
  int size;		 /* -1 if unknown at this point */
  bool getheader;	 /* TRUE if header parsing is wanted */
  long *bytecountp;	 /* return number of bytes read or NULL */
          
  /* WRITE stuff */
  int writesockfd;       /* socket to write to, it may very well be
                            the same we read from. -1 disables */
  long *writebytecountp; /* return number of bytes written or NULL */

#ifdef KRB4

  enum protection_level command_prot;
  enum protection_level data_prot;
  enum protection_level request_data_prot;

  size_t buffer_size;

  struct krb4buffer in_buffer, out_buffer;
  int sec_complete;
  void *app_data;

#endif
};

struct Progress {
  long lastshow; /* time() of the last displayed progress meter or NULL to
                    force redraw at next call */
  double size_dl;
  double size_ul;
  double downloaded;
  double uploaded;

  double current_speed; /* uses the currently fastest transfer */

  bool callback;  /* set when progress callback is used */
  int width; /* screen width at download start */
  int flags; /* see progress.h */
  double timespent;
  double dlspeed;
  double ulspeed;

  struct timeval start;
  struct timeval t_startsingle;
  /* various data stored for possible later report */
  double t_nslookup;
  double t_connect;
  double t_pretransfer;
  int httpcode;

#define CURR_TIME 5

  double speeder[ CURR_TIME ];
  int speeder_c;
};

/****************************************************************************
 * HTTP unique setup
 ***************************************************************************/
struct HTTP {
  struct FormData *sendit;
  int postsize;
  char *p_pragma;
  char *p_accept;
  long readbytecount;
  long writebytecount;

  /* For FORM posting */
  struct Form form;
  size_t (*storefread)(char *, size_t , size_t , FILE *);
  FILE *in;
};

/****************************************************************************
 * FTP unique setup
 ***************************************************************************/
struct FTP {
  long *bytecountp;
  char *user;
  char *passwd;
  char *urlpath; /* the originally given path part of the URL */
  char *dir;     /* decoded directory */
  char *file;    /* decoded file */
};

struct Configbits {
  bool tunnel_thru_httpproxy;
  bool ftp_append;
  bool ftp_ascii;
  bool ftp_list_only;
  bool ftp_use_port;
  bool hide_progress;
  bool http_fail_on_error;
  bool http_follow_location;
  bool http_formpost;
  bool http_include_header;
  bool http_post;
  bool http_put;
  bool http_set_referer;
  bool http_auto_referer; /* set "correct" referer when following location: */
  bool httpproxy;
  bool mute;
  bool no_body;
  bool proxy_user_passwd;
  bool set_port;
  bool set_range;
  bool upload;
  bool use_netrc;
  bool user_passwd;
  bool verbose;
  bool this_is_a_follow; /* this is a followed Location: request */
  bool krb4; /* kerberos4 connection requested */

  bool proxystringalloc; /* the http proxy string is malloc()'ed */
  bool rangestringalloc; /* the range string is malloc()'ed */
  bool urlstringalloc;   /* the URL string is malloc()'ed */
};

/* What type of interface that intiated this struct */
typedef enum {
  CURLI_NONE,
  CURLI_EASY,
  CURLI_NORMAL,
  CURLI_LAST
} CurlInterface;

struct ssldata {
  bool use;              /* use ssl encrypted communications TRUE/FALSE */
  long version;          /* what version the client wants to use */
  long certverifyresult; /* result from the certificate verification */
  bool verifypeer;       /* set TRUE if this is desired */
  char *CApath;          /* DOES NOT WORK ON WINDOWS */
  char *CAfile;          /* cerficate to verify peer against */
#ifdef USE_SSLEAY
  /* these ones requires specific SSL-types */
  SSL_CTX* ctx;
  SSL*     handle;
  X509*    server_cert;
#endif /* USE_SSLEAY */
};

/*
 * As of April 11, 2000 we're now trying to split up the urldata struct in
 * three different parts:
 *
 * (Global)
 * 1 - No matter how many hosts and requests that are being performed, this
 *     goes for all of them.
 *
 * (Session)
 * 2 - Host and protocol-specific. No matter if we do several transfers to and
 *     from this host, these variables stay the same.
 *
 * (Request)
 * 3 - Request-specific. Variables that are of interest for this particular
 *     transfer being made right now.
 *
 */

struct UrlData {
  Handle handle; /* struct identifier */
  CurlInterface interf; /* created by WHAT interface? */

  /*************** Global - specific items  ************/
  FILE *err;    /* the stderr writes goes here */
  char *errorbuffer; /* store failure messages in here */

  /*************** Session - specific items ************/
  char *proxy; /* if proxy, set it here, set CONF_PROXY to use this */
  char *proxyuserpwd;  /* Proxy <user:password>, if used */
  long proxyport; /* If non-zero, use this port number by default. If the
                     proxy string features a ":[port]" that one will override
                     this. */

  
  long header_size;  /* size of read header(s) in bytes */
  long request_size; /* the amount of bytes sent in the request(s) */

  /*************** Request - specific items ************/

  union {
    struct HTTP *http;
    struct HTTP *gopher; /* alias, just for the sake of being more readable */
    struct HTTP *https;  /* alias, just for the sake of being more readable */
    struct FTP *ftp;
#if 0 /* no need for special ones for these: */
    struct TELNET *telnet;
    struct FILE *file;
    struct LDAP *ldap;
    struct DICT *dict;
#endif
    void *generic;
  } proto;

  FILE *out;    /* the fetched file goes here */
  FILE *in;     /* the uploaded file is read from here */
  FILE *writeheader; /* write the header to this is non-NULL */
  char *url;   /* what to get */
  char *freethis; /* if non-NULL, an allocated string for the URL */
  char *hostname; /* hostname to connect, as parsed from url */
  unsigned short port; /* which port to use (if non-protocol bind) set
                          CONF_PORT to use this */
  unsigned short remote_port; /* what remote port to connect to, not the proxy
				 port! */
  struct Configbits bits; /* new-style (v7) flag data */

  char *userpwd;  /* <user:password>, if used */
  char *range; /* range, if used. See README for detailed specification on
                  this syntax. */

  /* stuff related to HTTP */

  long followlocation;
  char *referer;
  bool free_referer; /* set TRUE if 'referer' points to a string we
                        allocated */
  char *useragent;   /* User-Agent string */
  char *postfields; /* if POST, set the fields' values here */
  long postfieldsize; /* if POST, this might have a size to use instead of
                         strlen(), and then the data *may* be binary (contain
                         zero bytes) */

  /* stuff related to FTP */
  char *ftpport; /* port to send with the PORT command */

  /* general things */
  char *device;  /* Interface to use */

  /* function that stores the output:*/
  curl_write_callback fwrite;

  /* function that reads the input:*/
  curl_read_callback fread;

  /* function that wants progress information */
  curl_progress_callback fprogress;
  void *progress_client; /* pointer to pass to the progress callback */

  /* function to call instead of the internal for password */
  curl_passwd_callback fpasswd;
  void *passwd_client; /* pointer to pass to the passwd callback */

  long timeout; /* in seconds, 0 means no timeout */
  long infilesize; /* size of file to upload, -1 means unknown */

  long maxdownload; /* in bytes, the maximum amount of data to fetch, 0
                       means unlimited */
  
  /* fields only set and used within _urlget() */
  int firstsocket;     /* the main socket to use */
  int secondarysocket; /* for i.e ftp transfers */

  char buffer[BUFSIZE+1]; /* buffer with size BUFSIZE */

  double current_speed;  /* the ProgressShow() funcion sets this */

  long low_speed_limit; /* bytes/second */
  long low_speed_time;  /* number of seconds */

  int resume_from;    /* continue [ftp] transfer from here */

  char *cookie;       /* HTTP cookie string to send */

  char *newurl; /* This can only be set if a Location: was in the
		   document headers */

  struct curl_slist *headers; /* linked list of extra headers */
  struct HttpPost *httppost;  /* linked list of POST data */

  char *cert; /* PEM-formatted certificate */
  char *cert_passwd; /* plain text certificate password */

  struct CookieInfo *cookies;

  struct ssldata ssl; /* this is for ssl-stuff */

  long crlf;
  struct curl_slist *quote;     /* before the transfer */
  struct curl_slist *postquote; /* after the transfer */

  TimeCond timecondition;
  time_t timevalue;

  char *customrequest; /* http/ftp request to use */

  char *headerbuff; /* allocated buffer to store headers in */
  int headersize;   /* size of the allocation */

#if 0
  /* this was removed in libcurl 7.4 */
  char *writeinfo;  /* if non-NULL describes what to output on a successful
                       completion */
#endif

  struct Progress progress;

#define MAX_CURL_USER_LENGTH 128
#define MAX_CURL_PASSWORD_LENGTH 128

  char *auth_host; /* if set, this is the allocated string to the host name
                    * to which to send the authorization data to, and no other
                    * host (which location-following otherwise could lead to)
                    */

  char user[MAX_CURL_USER_LENGTH];
  char passwd[MAX_CURL_PASSWORD_LENGTH];
  char proxyuser[MAX_CURL_USER_LENGTH];
  char proxypasswd[MAX_CURL_PASSWORD_LENGTH];

  /**** Dynamicly allocated strings, may need to be freed on return ****/
  char *ptr_proxyuserpwd; /* free later if not NULL! */
  char *ptr_uagent; /* free later if not NULL! */
  char *ptr_userpwd; /* free later if not NULL! */
  char *ptr_rangeline; /* free later if not NULL! */
  char *ptr_ref; /* free later if not NULL! */
  char *ptr_cookie; /* free later if not NULL! */
  char *ptr_host; /* free later if not NULL */

  char *krb4_level;
#ifdef KRB4
  FILE *cmdchannel;
#endif

  struct timeval keeps_speed; /* this should be request-specific */
};

#define LIBCURL_NAME "libcurl"
#define LIBCURL_ID LIBCURL_NAME " " LIBCURL_VERSION " " SSL_ID


#endif
