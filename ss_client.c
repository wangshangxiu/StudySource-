/*
 * nghttp2 - HTTP/2 C Library
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif /* HAVE_NETDB_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <linux/sockios.h> //ioctl
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>
#include <poll.h>
#include <memory.h>

#include <netdb.h>

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#ifdef NGHTTP2_NORETURN
#define NGHTTP2_NORETURN
#endif

enum { IO_NONE, WANT_READ, WANT_WRITE };

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE),    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),        \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }




static void deflate(nghttp2_hd_deflater *deflater,
                    nghttp2_hd_inflater *inflater, const nghttp2_nv *const nva,
                    size_t nvlen);

static int inflate_header_block(nghttp2_hd_inflater *inflater, uint8_t *in,
                                size_t inlen, int final);

int hpackInit(nghttp2_hd_deflater *deflater, nghttp2_hd_inflater *inflater) 
{
  int rv;

  rv = nghttp2_hd_deflate_new(&deflater, 4096);

  if (rv != 0) {
    fprintf(stderr, "nghttp2_hd_deflate_init failed with error: %s\n",
            nghttp2_strerror(rv));
    exit(EXIT_FAILURE);
  }

  rv = nghttp2_hd_inflate_new(&inflater);

  if (rv != 0) {
    fprintf(stderr, "nghttp2_hd_inflate_init failed with error: %s\n",
            nghttp2_strerror(rv));
    exit(EXIT_FAILURE);
  }

  return 0;
}


int hpackUnInit(nghttp2_hd_deflater *deflater, nghttp2_hd_inflater *inflater) 
{
	nghttp2_hd_inflate_del(inflater);
	nghttp2_hd_deflate_del(deflater);
}

static void deflate(nghttp2_hd_deflater *deflater,
                    nghttp2_hd_inflater *inflater, const nghttp2_nv *const nva,
                    size_t nvlen) {
  ssize_t rv;
  uint8_t *buf;
  size_t buflen;
  size_t outlen;
  size_t i;
  size_t sum;

  sum = 0;

  for (i = 0; i < nvlen; ++i) {
    sum += nva[i].namelen + nva[i].valuelen;
  }

  printf("Input (%zu byte(s)):\n\n", sum);

  for (i = 0; i < nvlen; ++i) {
    fwrite(nva[i].name, 1, nva[i].namelen, stdout);
    printf(": ");
    fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
    printf("\n");
  }

  buflen = nghttp2_hd_deflate_bound(deflater, nva, nvlen);
  buf = malloc(buflen);

  rv = nghttp2_hd_deflate_hd(deflater, buf, buflen, nva, nvlen);

  if (rv < 0) {
    fprintf(stderr, "nghttp2_hd_deflate_hd() failed with error: %s\n",
            nghttp2_strerror((int)rv));

    free(buf);

    exit(EXIT_FAILURE);
  }

  outlen = (size_t)rv;

  printf("\nDeflate (%zu byte(s), ratio %.02f):\n\n", outlen,
         sum == 0 ? 0 : (double)outlen / (double)sum);

  for (i = 0; i < outlen; ++i) {
    if ((i & 0x0fu) == 0) {
      printf("%08zX: ", i);
    }

    printf("%02X ", buf[i]);

    if (((i + 1) & 0x0fu) == 0) {
      printf("\n");
    }
  }

  printf("\n\nInflate:\n\n");

  /* We pass 1 to final parameter, because buf contains whole deflated
     header data. */
  rv = inflate_header_block(inflater, buf, outlen, 1);

  if (rv != 0) {
    free(buf);

    exit(EXIT_FAILURE);
  }

  printf("\n-----------------------------------------------------------"
         "--------------------\n");

  free(buf);
}

int inflate_header_block(nghttp2_hd_inflater *inflater, uint8_t *in,
                         size_t inlen, int final) {
  ssize_t rv;

  for (;;) {
    nghttp2_nv nv;
    int inflate_flags = 0;
    size_t proclen;

    rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, in, inlen, final);

    if (rv < 0) {
      fprintf(stderr, "inflate failed with error code %zd", rv);
      return -1;
    }

    proclen = (size_t)rv;

    in += proclen;
    inlen -= proclen;

    if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
      fwrite(nv.name, 1, nv.namelen, stderr);
      fprintf(stderr, ": ");
      fwrite(nv.value, 1, nv.valuelen, stderr);
      fprintf(stderr, "\n");
    }

    if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
      nghttp2_hd_inflate_end_headers(inflater);
      break;
    }

    if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
      break;
    }
  }

  return 0;
}

struct Connection {
  SSL *ssl;
  nghttp2_session *session;
  /* WANT_READ if SSL/TLS connection needs more input; or WANT_WRITE
     if it needs more output; or IO_NONE. This is necessary because
     SSL/TLS re-negotiation is possible at any time. nghttp2 API
     offers similar functions like nghttp2_session_want_read() and
     nghttp2_session_want_write() but they do not take into account
     SSL/TSL connection. */
  int want_io;
};

struct Request {
  char *host;
  /* In this program, path contains query component as well. */
  char *path;
  /* This is the concatenation of host and port with ":" in
     between. */
  char *hostport;
  /* Stream ID for this request. */
  int32_t stream_id;
  uint16_t port;


  struct Connection *connect;
};

struct URI {
  const char *host;
  /* In this program, path contains query component as well. */
  const char *path;
  size_t pathlen;
  const char *hostport;
  size_t hostlen;
  size_t hostportlen;
  uint16_t port;
};

/*
 * Returns copy of string |s| with the length |len|. The returned
 * string is NULL-terminated.
 */
static char *strcopy(const char *s, size_t len) {
  char *dst;
  dst = malloc(len + 1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

/*
 * Prints error message |msg| and exit.
 */
//NGHTTP2_NORETURN
static void die(const char *msg) {
  fprintf(stderr, "FATAL: %s\n", msg);
  exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and message |msg|
 * and exit.
 */
//NGHTTP2_NORETURN
static void dief(const char *func, const char *msg) {
  fprintf(stderr, "FATAL: %s: %s\n", func, msg);
  exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and error code
 * |error_code| and exit.
 */
//NGHTTP2_NORETURN
static void diec(const char *func, int error_code) {
  fprintf(stderr, "FATAL: %s: error_code=%d, msg=%s\n", func, error_code,
          nghttp2_strerror(error_code));
  exit(EXIT_FAILURE);
}

/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
   struct Connection *connection;
  int rv;
  (void)session;
  (void)flags;

  struct Request *req =  (struct Request *)user_data;

  //(1);
 connection = req->connect;


  printf("send_callback:%s, length:%d\n", data, length);



	char *tmpTest = (char *)data;
	int i;
	for (i = 0; i < length; i++)
	{
		printf("%d", tmpTest[i]);
	}
	printf("\n");

  //printf("sslsslsslssl recv_callback length:%d\n", rv);


/*
  if (length < 30)                
  {                               
      int i = 0;                  
        for(;i < length; i++)     
        {                         
            printf("%x", data[i]);
        }                         
        printf("\n");             
                                  
  }                               
*/

 // connection = (struct Connection *)user_data;
  connection->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_write(connection->ssl, data, (int)length);
  if (rv <= 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data) {
  struct Connection *connection;
  int rv;
  (void)session;
  (void)flags;

  struct Request *req =  (struct Request *)user_data;

  //(1);
  memset(buf, 0, length);
 printf("sslsslsslssl recv_callback length:%d\n", length);
 connection = req->connect;

  connection->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_read(connection->ssl, buf, (int)length);

  if (rv < 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if (rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }

   //printf("sslsslsslssl recv_callback length:%d\n", rv);

/*
   if (rv > 0)                   
   {                             
       int i = 0;                
        for(;i < rv; i++)        
        {                        
            printf("%x", buf[i]);
        }                        
        printf("\n");            
   }                             
*/
  return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  size_t i;
  (void)user_data;


	printf("frame send callback!\n");

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {

		return 0;
      const nghttp2_nv *nva = frame->headers.nva;
      printf("[INFO] C ----------------------------> S (HEADERS)\n");
      for (i = 0; i < frame->headers.nvlen; ++i) {
        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
        printf(": ");
        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
        printf("\n");
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C ----------------------------> S (GOAWAY)\n");
    break;
  }
  return 0;
}

static int decode_status_code(const uint8_t *value, size_t len)
{
  int i;
  int res;

  if(len != 3) {
    return -1;
  }

  res = 0;

  for(i = 0; i < 3; ++i) {
    char c = value[i];

    if(c < '0' || c > '9') {
      return -1;
    }

    res *= 10;
    res += c - '0';
  }

  return res;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp)
{
  

	//printf("on_header call back");

	//printf("on_header type :%d\n", frame->hd.type);
  int32_t stream_id = frame->hd.stream_id;

  //DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
   //nghttp2_session_get_stream_user_data(session, stream_id);
  /* Store received PUSH_PROMISE headers to be used when the subsequent
     PUSH_PROMISE callback comes */
  if(frame->hd.type == NGHTTP2_HEADERS)
  {
    char *h;

	int i  = decode_status_code(value, valuelen);


	printf("%s: %s\n", name, value);
  }
  else
  {
	  printf("on_header type:%d, %s: %s\n", name, value);
  }


  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  size_t i;
	printf("[INFO] C<-------- S (HEADERS)nghttp2_frame_type:%d,stream_id:%d\n", frame->hd.type, frame->hd.stream_id);

  switch (frame->hd.type) {
  case NGHTTP2_SETTINGS:
    printf("iframe->settings.niv:%d\n", frame->settings.niv);
	  break;
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
		 struct Request *req;
		req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      const nghttp2_nv *nva = frame->headers.nva;
      if (req) {
        printf("[INFO] C <---------------------------- S (HEADERS)\n");
		//printf("padlen: %d\n", frame->headers.);
		//printf("head size:%d, %s, nvlen:%d\n", strlen((char *)frame), (char*)frame, frame->headers.nvlen);

		printf("frame->headers.cat:%d \nframe->headers.hd.flags:%d \nframe->headers.hd.length:%d \nframe->headers.hd.reserved:%d \nframe->headers.hd.stream_id:%d \nframe->headers.hd.type:%d\n", 
			   frame->headers.cat, frame->headers.hd.flags, frame->headers.hd.length, frame->headers.hd.reserved,
			    frame->headers.hd.stream_id, frame->headers.hd.type);
		printf("frame->headers.nvlen:%d \nframe->headers.padlen:%d \nframe->headers.pri_spec.stream_id:%d \nframe->headers.pri_spec.exclusive:%d \nframe->headers.pri_spec.weight:%d \n", 
			   frame->headers.nvlen, frame->headers.padlen, frame->headers.pri_spec.stream_id, 
			   frame->headers.pri_spec.exclusive, frame->headers.pri_spec.weight);

        for (i = 0; nva; nva++, i++) {
          fwrite(nva->name, 1, nva->namelen, stdout);
          printf(": ");
          fwrite(nva->value, 1, nva->valuelen, stdout);
          printf("\n");
        }
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C <---------------------------- S (GOAWAY)\n");
    break;
  case NGHTTP2_DATA:
	  printf("frame->data.hd.flags:%d \nframe->data.hd.length:%d \nframe->data.hd.reserved:%d \nframe->data.hd.stream_id:%d \nframe->data.hd.type:%d\n", 
			 frame->data.hd.flags, frame->data.hd.length, frame->data.hd.reserved,
			    frame->data.hd.stream_id, frame->data.hd.type);
	  printf("frame->data.padlen:%d\n", frame->data.padlen);

	  break;
  default:
	  printf("[INFO] C <-++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---S\n");
	  break;
  }


  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  struct Request *req =  (struct Request *)user_data; 

    printf("on_stream_close_callback\n");
	//return 0;
  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (req) {
    int rv = 0;
    //rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

    if (rv != 0) {
      diec("nghttp2_session_terminate_session", rv);
    }
  }


  //sleep(3);
  return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
  struct Request *req;
  (void)flags;
  (void)user_data;


  printf("on_data_chunk_recv_callback\n");

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (req) {
    printf("[INFO] C <---------------------------- S (DATA chunk)\n"
           "%lu bytes\n",
           (unsigned long int)len);
    fwrite(data, 1, len, stdout);
    printf("\n");
  }
  return 0;
}

int on_unpack_extension_callback(nghttp2_session *session,
                                                 void **payload,
                                                 const nghttp2_frame_hd *hd,
                                                 void *user_data)
{
	printf("on_frame_send_callback, type:%d\n", hd->type);
}

int onextension_chunk_recv_callback(nghttp2_session *session, const nghttp2_frame_hd *hd, const uint8_t *data,
    size_t len, void *user_data)
{
	printf("on_extension_chunk_recv_callback, type:%d\n", hd->type);
}


/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * recv_callback is also required.
 */
static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks) {
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);

  
 //nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);

  //nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
 //                                                      on_frame_recv_callback);

  
  //nghttp2_session_callbacks_set_on_stream_close_callback(
   //   callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);


  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
//nghttp2_session_callbacks_set_on_extension_chunk_recv_callback(
//	callbacks, onextension_chunk_recv_callback);

//nghttp2_session_callbacks_set_unpack_extension_callback(
//	callbacks, on_unpack_extension_callback);

}

/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  int rv;
  (void)ssl;
  (void)arg;

  /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
  rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
  if (rv <= 0) {
    die("Server did not advertise HTTP/2 protocol");
  }
  return SSL_TLSEXT_ERR_OK;
}

/*
 * Setup SSL/TLS context.
 */
static void init_ssl_ctx(SSL_CTX *ssl_ctx) {
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  /* Set NPN callback */
  //SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static void ssl_handshake(SSL *ssl, int fd) 
{

  int rv;
  if (SSL_set_fd(ssl, fd) == 0) {
    dief("SSL_set_fd", ERR_error_string(ERR_get_error(), NULL));
  }
  ERR_clear_error();
  rv = SSL_connect(ssl);
  if (rv <= 0) {
    dief("SSL_connect", ERR_error_string(ERR_get_error(), NULL));
  }
}

/*
 * Connects to the host |host| and port |port|.  This function returns
 * the file descriptor of the client socket.
 */
static int connect_to(const char *host, uint16_t port) {
  struct addrinfo hints;
  int fd = -1;
  int rv;
  char service[NI_MAXSERV];
  struct addrinfo *res, *rp;
  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rv = getaddrinfo(host, service, &hints, &res);
  if (rv != 0) {
    dief("getaddrinfo", gai_strerror(rv));
  }
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }
    while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
           errno == EINTR)
      ;
    if (rv == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static void make_non_block(int fd) {
  int flags, rv;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;
  if (flags == -1) {
    dief("fcntl", strerror(errno));
  }
  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;
  if (rv == -1) {
    dief("fcntl", strerror(errno));
  }
}

static void set_tcp_nodelay(int fd) {
  int val = 1;
  int rv;
  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
  if (rv == -1) {
    dief("setsockopt", strerror(errno));
  }
}

/*
 * Update |pollfd| based on the state of |connection|.
 */
static void ctl_poll(struct pollfd *pollfd, struct Connection *connection) {
  pollfd->events = 0;
  if (nghttp2_session_want_read(connection->session) ||
      connection->want_io == WANT_READ) {
    pollfd->events |= POLLIN;
  }
  if (nghttp2_session_want_write(connection->session) ||
      connection->want_io == WANT_WRITE) {
    pollfd->events |= POLLOUT;
  }
}

static char payload[1024] = "{\"aps\": {\"badge\": 2,\"category\": \"mycategory\",\"alert\": {\"title\": \"liulang test title\",\"body\": \" liulang text message\"}}}\r\n\n";
struct request_t {
	uint8_t *data;
	size_t data_len;
};

ssize_t data_prd_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
	uint32_t *data_flags, nghttp2_data_source *source, void *user_data) 
{
	memcpy(buf, payload, strlen(payload));
	*data_flags = *data_flags | NGHTTP2_DATA_FLAG_EOF;

	printf("[INFO] C ----------------------------> S (DATA post body)\n");
	return strlen(payload);
}

/*
 *  * Submits the request |req| to the connection |connection|.  This
 *   * function does not send packets; just append the request to the
 *    * internal queue in |connection->session|.
 *     */
static void submit_request(struct Connection *connection, struct Request *req) {
  int32_t stream_id;
  /* Make sure that the last item is NULL */
  //int len = strlen(payload);
  //char slen[10] = {0};
 // sprintf(slen, "%d", strlen(payload));

  const nghttp2_nv nva[] = {
							MAKE_NV(":method", "POST"),
							//MAKE_NV(":scheme", "https"),
							MAKE_NV(":path", "/3/device/dff10bdcf84e3d71bfb9571f1d80262736efc4bbf2d5facec19a9ff2675e4406"),
                            //MAKE_NV("host", "api.development.push.apple.com"),
							//MAKE_NV("User-Agent", "nghttp2"),
							//MAKE_NV("accept", "*/*"),
						    MAKE_NV("apns-id", "DD6ECE2F-035E-4A14-81BD-F2618AAAD102"),
	                        //MAKE_NV("content-type", "application/json"),
							MAKE_NV("apns-topic", "com.onlyy.huhu"), //com.onlyy.huhu
							MAKE_NV("authorization", 
"bearer eyAiYWxnIjogIkVTMjU2IiwgImtpZCI6ICI1OTQ2MzJRSDdKIiB9.eyAiaXNzIjogIlBGOUhRSldMMjQiLCAiaWF0IjogMTUxMDI4MjAzMCB9.ZlOm1Dr3tN3wIHmgFtTTFrXompxIzn-Yb9U9aMJHa8AomKI4ChLL5OypPKS4jb5qZZuqsnsbvtfZ7vyKIH-yShA")};
//"bearer eyAiYWxnIjogIkVTMjU2IiwgImtpZCI6ICI1UzdXODI5WFlFIiB9.eyAiaXNzIjogIlBGOUhRSldMMjQiLCAiaWF0IjogMTUwMTY1OTg0MyB9./")};
							//MAKE_NV_CS("Content-Length", slen)};

/*
 
method:POST
path:/3/device/dff10bdcf84e3d71bfb9571f1d80262736efc4bbf2d5facec19a9ff2675e4406
apns-id:73DD87AD-EAE9-4220-B895-0828771AA0FA
apns-topic:com.onlyy.huhu
authorization:bearer eyAiYWxnIjogIkVTMjU2IiwgImtpZCI6ICI1OTQ2MzJRSDdKIiB9.eyAiaXNzIjogIlBGOUhRSldMMjQiLCAiaWF0IjogMTUxMDEzMTI3NyB9.JOX7Sf63ChUna3EXJgkvbdw-6xprE-K_hkBTAf7Gg5ZBQE2-iJyTz04DVAF4Hu3ksi9M5Lm-xdDml2PaF17JxRA
 
 
 
*/

  struct request_t t;

  nghttp2_data_provider provider;

  provider.source.ptr = &t;
  provider.read_callback = data_prd_read_callback;

  stream_id = nghttp2_submit_request(connection->session, NULL, nva,
                                     sizeof(nva) / sizeof(nva[0]), &provider, req);
  if (stream_id < 0) {
    diec("nghttp2_submit_request", stream_id);
  }

  req->stream_id = stream_id;
  printf("[INFO] Stream ID = %d\n", stream_id);

}



int i=0;
int t = 0;
/*
 * Performs the network I/O.
 */
static void exec_io(struct Connection *connection) {

  int rv;
  rv = nghttp2_session_recv(connection->session);
  //printf("nghttp2_session_recv\n");
  if (rv != 0) {
    diec("nghttp2_session_recv", rv);
  }
  
  rv = nghttp2_session_send(connection->session);
  //printf("nghttp2_session_send\n");
  if (rv != 0) {
	diec("nghttp2_session_send", rv);
  }

  //nghttp2_submit_request();

  //nghttp2_submit_response()
}


static void exec_i(struct Request *req) {


/*
    char buf[1024];                                    
                                                       
     int t = SSL_read(connection->ssl, buf, (int)1024);
                                                       
     printf("buf:%s, %d\n", buf, strlen(buf));         
                                                       
                                                       
*/
  int rv;
  rv = nghttp2_session_recv(req->connect->session);
  //printf("nghttp2_session_recv\n");
  if (rv != 0) {
    diec("nghttp2_session_recv", rv);
  }
}


static void exec_o(struct Request *req) 
{


	//sleep(1);
  int rv = 0;
  rv = nghttp2_session_send(req->connect->session);
  printf("nghttp2_session_send\n");
  if (rv != 0) {
	//diec("nghttp2_session_send", rv);
  }
  

  submit_request(req->connect, req);

}



static void request_init(struct Request *req, const struct URI *uri) {
  req->host = strcopy(uri->host, uri->hostlen);
  req->port = uri->port;
  req->path = strcopy(uri->path, uri->pathlen);
  req->hostport = strcopy(uri->hostport, uri->hostportlen);
  req->stream_id = -1;
}

static void request_free(struct Request *req) {
  free(req->host);
  free(req->path);
  free(req->hostport);
}



char *cert_file = "cer.pem";
char *key_file = "rsapk.pem";
/*
 * Fetches the resource denoted by |uri|.
 */

int testbool = 0;
static void fetch_uri(const struct URI *uri) {
  nghttp2_session_callbacks *callbacks;
  int fd;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  struct Request req;
  struct Connection connection;
  int rv;
  nfds_t npollfds = 1;
  struct pollfd pollfds[1];

  request_init(&req, uri);

  /* Establish connection and setup SSL */
  fd = connect_to(req.host, req.port);
  if (fd == -1) {
    die("Could not open file descriptor");
  }
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (ssl_ctx == NULL) {
    dief("SSL_CTX_new", ERR_error_string(ERR_get_error(), NULL));
  }
  init_ssl_ctx(ssl_ctx);
  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    dief("SSL_new", ERR_error_string(ERR_get_error(), NULL));
  }


  /*

  int nRet;

      if(!(nRet = SSL_CTX_use_certificate_file
         (ssl_ctx, cert_file, SSL_FILETYPE_PEM)))
    {
        int32_t nErrorCode = SSL_get_error(ssl, nRet);
        printf("init ssl: use certificate file failed.errno: %d.", nErrorCode);
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
        return ;
    }


    //SSL_CTX_use_PrivateKey_file()        //为SSL会话加载本应用的私钥
    //SSL_CTX_set_default_passwd_cb_userdata(GetSSLCTX(),(void *) key_password);

    nRet = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM);
    if(!nRet)
    {
        int32_t nErrorCode = SSL_get_error(ssl, nRet);
        printf("init ssl: use PrivateKey file failed.errno: %d.", nErrorCode);
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
        return ;
    }
*/
  /* To simplify the program, we perform SSL/TLS handshake in blocking
     I/O. */
  ssl_handshake(ssl, fd);

  connection.ssl = ssl;
  connection.want_io = IO_NONE;

  /* Here make file descriptor non-block */
  make_non_block(fd);
  set_tcp_nodelay(fd);

  printf("[INFO] SSL/TLS handshake completed\n");

  rv = nghttp2_session_callbacks_new(&callbacks);

  if (rv != 0) {
    diec("nghttp2_session_callbacks_new", rv);
  }

  
  setup_nghttp2_callbacks(callbacks);

/*
  nghttp2_option *option;

nghttp2_option_new(&option);

  //option->no_closed_streams = 1000;

  //nghttp2_option_set_max_reserved_remote_streams(option, 100);
 nghttp2_option_set_no_closed_streams(option, 2);

  //nghttp2_option_set_peer_max_concurrent_streams(option, 1000);

  rv = nghttp2_session_client_new2(&connection.session, callbacks, &connection, option);

*/

req.connect = &connection;
  rv = nghttp2_session_client_new(&connection.session, callbacks, &req);

  nghttp2_session_callbacks_del(callbacks);

  if (rv != 0) {
    diec("nghttp2_session_client_new", rv);
  }

  //nghttp2_settings_entry
  rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_ACK, NULL, 0);

  if (rv != 0) {
    diec("nghttp2_submit_settings", rv);
  }

  printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

  /* Submit the HTTP request to the outbound queue. */
  //submit_request(&connection, &req);

  printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  pollfds[0].fd = fd;
  ctl_poll(pollfds, &connection);

  //sleep(1111);
  /* Event loop */
 // while (nghttp2_session_want_read(connection.session) ||
  //       nghttp2_session_want_write(connection.session))

	  while (1)
	  {
    int nfds = poll(pollfds, npollfds, 50);
 
	if (0 == nfds)
	{
			//submit_request(&connection, &req);
		printf("time out!\n");
		testbool = 1;
	}

	if (nfds == -1)
	{
      dief("poll", strerror(errno));
    }

    if (pollfds[0].revents & (POLLIN)) {
      exec_i(&req);
    }

	if (pollfds[0].revents & POLLOUT)
	{
		//test
		if (1)
		{
		int t;
		int value = 0;
		int size = 0;
		int iRet = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&size, (socklen_t *)&t);
		if (iRet != 0)
		{
			printf("getsockopt error\n");
		}

		//iRet = ioctl(fd, SIOCOUTQ, &value);
		if (iRet != 0)
		{
			printf("ioctl error\n");
		}
			printf("totle:%d, cache:%d, send:%d\n", size, size-value, value);
		}

		exec_o(&req);
		if (testbool)
		{
			//sleep(1);
			//sleep(20);
		}
	}
	
    if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      die("Connection error");
    }
    ctl_poll(pollfds, &connection);

	
	sleep(1);
	//break;
  }

  sleep(5);

  /* Resource cleanup */
  nghttp2_session_del(connection.session);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  request_free(&req);
}

static int parse_uri(struct URI *res, const char *uri) {
  /* We only interested in https */
  size_t len, i, offset;
  int ipv6addr = 0;
  memset(res, 0, sizeof(struct URI));
  len = strlen(uri);
  if (len < 9 || memcmp("https://", uri, 8) != 0) {
    return -1;
  }
  offset = 8;
  res->host = res->hostport = &uri[offset];
  res->hostlen = 0;
  if (uri[offset] == '[') {
    /* IPv6 literal address */
    ++offset;
    ++res->host;
    ipv6addr = 1;
    for (i = offset; i < len; ++i) {
      if (uri[i] == ']') {
        res->hostlen = i - offset;
        offset = i + 1;
        break;
      }
    }
  } else {
    const char delims[] = ":/?#";
    for (i = offset; i < len; ++i) {
      if (strchr(delims, uri[i]) != NULL) {
        break;
      }
    }
    res->hostlen = i - offset;
    offset = i;
  }
  if (res->hostlen == 0) {
    return -1;
  }
  /* Assuming https */
  res->port = 443;
  if (offset < len) {
    if (uri[offset] == ':') {
      /* port */
      const char delims[] = "/?#";
      int port = 0;
      ++offset;
      for (i = offset; i < len; ++i) {
        if (strchr(delims, uri[i]) != NULL) {
          break;
        }
        if ('0' <= uri[i] && uri[i] <= '9') {
          port *= 10;
          port += uri[i] - '0';
          if (port > 65535) {
            return -1;
          }
        } else {
          return -1;
        }
      }
      if (port == 0) {
        return -1;
      }
      offset = i;
      res->port = (uint16_t)port;
    }
  }
  res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);
  for (i = offset; i < len; ++i) {
    if (uri[i] == '#') {
      break;
    }
  }
  if (i - offset == 0) {
    res->path = "/";
    res->pathlen = 1;
  } else {
    res->path = &uri[offset];
    res->pathlen = i - offset;
  }
  return 0;
}

int main(int argc, char **argv) {
  struct URI uri;
  struct sigaction act;
  int rv;


  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  rv = parse_uri(&uri, "https://api.development.push.apple.com");
  if (rv != 0) {
    die("parse_uri failed");
  }
  fetch_uri(&uri);
  return EXIT_SUCCESS;
}
