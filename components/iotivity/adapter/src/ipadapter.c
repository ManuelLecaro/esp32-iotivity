/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <freertos/FreeRTOS.h>
#include "freertos/semphr.h"
#include "lwip/mld6.h"
#include "lwip/sockets.h"
#include "esp_system.h"
#include <assert.h>
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "messaging/coap/coap.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "debug_print.h"
#include "esp_wifi.h"
#include "lwip/err.h"
#include <lwip/netdb.h>
#include "esp_log.h"

#include "tcpip_adapter.h"
#include "esp_ipcontext.h"
#include "util/oc_memb.h"
#include "esp_oc_context.h"
#include "tcpadapter.h"
#include "coap_config_posix.h"                    /**< para definiciones de IP_PKTINFO E IPV6_PKTINFO */

static const char* TAG = "ipadapter";

/* most of function declaration is under iotivity-constrained/port/oc_connectivity.h 
 and oc_network_events_mutex.h */
#ifndef IFA_MULTICAST
#define IFA_MULTICAST 7
#endif

/* Some outdated toolchains do not define IFA_FLAGS.
   Note: Requires Linux kernel 3.14 or later. */
#ifndef IFA_FLAGS
#define IFA_FLAGS (IFA_MULTICAST+1)
#endif

static const uint8_t ALL_OCF_NODES_LL[] = {
  0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
static const uint8_t ALL_OCF_NODES_RL[] = {
  0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
static const uint8_t ALL_OCF_NODES_SL[] = {
  0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58
};
#define ALL_COAP_NODES_V4 0xe00001bb

/*  
  Number of Ports for CoAP, CoAPs, CoAP+TCP and CoAPs+TCP 
 */
#define OCF_PORT_UNSECURED (5683)
#define OCF_PORT_SECURE (5684)
#define OCF_PORT_TCP (34987)
#define OC_PORT_TCP_UNSECURE (35987)

#ifdef OC_DYNAMIC_ALLOCATION
OC_LIST(ip_contexts);
OC_LIST(session_list);
#else                                                     /* OC_DYNAMIC_ALLOCATION */
static ip_context_t devices[OC_MAX_NUM_DEVICES];
#endif                                                    /* !OC_DYNAMIC_ALLOCATION */

static pthread_mutex_t mutex;
OC_MEMB(device_eps, oc_endpoint_t, 8 * OC_MAX_NUM_DEVICES); // fix

#ifdef OC_TCP
OC_MEMB(tcp_session_s, tcp_session_t, OC_MAX_TCP_PEERS);
#endif

#define OC_TCP_LISTEN_BACKLOG 3

#define TLS_HEADER_SIZE 5

#define DEFAULT_RECEIVE_SIZE                                                   \
  (COAP_TCP_DEFAULT_HEADER_LEN + COAP_TCP_MAX_EXTENDED_LENGTH_LEN)

#define LIMIT_RETRY_CONNECT 5

#define TCP_CONNECT_TIMEOUT 5

void
oc_network_event_handler_mutex_init(void)
{
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex\n");
  }
}

void
oc_network_event_handler_mutex_lock(void)
{
  pthread_mutex_lock(&mutex);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  pthread_mutex_unlock(&mutex);
}

void oc_network_event_handler_mutex_destroy(void) {
  pthread_mutex_destroy(&mutex);
}

/**
 *    Get an ip_context struct according to the device number
 */
static ip_context_t *
get_ip_context_for_device(int device) {
#ifdef OC_DYNAMIC_ALLOCATION
  ip_context_t *dev = oc_list_head(ip_contexts);
  while (dev != NULL && dev->device != device) {
    dev = dev->next;
  }
  if (!dev) {
    return NULL;
  }
#else                                           /* OC_DYNAMIC_ALLOCATION */
  ip_context_t *dev = &devices[device];
#endif                                          /* !OC_DYNAMIC_ALLOCATION */
  return dev;
}

/**************************************************************************
 * *********************TCP Implementation*********************************
 * ************************************************************************/

/**
 *  Set flags for TCP sockets
 */
static int
configure_tcp_socket(int sock, struct sockaddr_storage *sock_info)
{
  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d", errno);
    return -1;
  }
  if (bind(sock, (struct sockaddr *)sock_info, sizeof(*sock_info)) == -1) {
    OC_ERR("binding socket %d", errno);
    return -1;
  }
  if (listen(sock, OC_TCP_LISTEN_BACKLOG) == -1) {
    OC_ERR("listening socket %d", errno);
    return -1;
  }

  return 0;
}

/**
 *  Get port numbers used on TCP connection
 */
static int
get_assigned_tcp_port(int sock, struct sockaddr_storage *sock_info)
{

  socklen_t socklen = sizeof(*sock_info);
  if (getsockname(sock, (struct sockaddr *)sock_info, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }

  return 0;
}

/**
 * Add sockets to file descriptors for a device
 */
void
oc_tcp_add_socks_to_fd_set(ip_context_t *dev)
{
  FD_SET(dev->tcp.server_sock, &dev->rfds);
#ifdef OC_SECURITY
  FD_SET(dev->tcp.secure_sock, &dev->rfds);
#endif                                                    /* OC_SECURITY */

#ifdef OC_IPV4
  FD_SET(dev->tcp.server4_sock, &dev->rfds);
#ifdef OC_SECURITY
  FD_SET(dev->tcp.secure4_sock, &dev->rfds);
#endif                                                    /* OC_SECURITY */
#endif                                                    /* OC_IPV4 */

}

static int
add_new_session(int sock, ip_context_t *dev, oc_endpoint_t *endpoint,
                tcp_csm_state_t state)
{
  tcp_session_t *session = oc_memb_alloc(&tcp_session_s);
  if (!session) {
    OC_ERR("could not allocate new TCP session object");
    return -1;
  }

  endpoint->interface_index = NULL;

  session->dev = dev;
  memcpy(&session->endpoint, endpoint, sizeof(oc_endpoint_t));
  session->endpoint.next = NULL;
  session->sock = sock;
  session->csm_state = state;

  oc_list_add(session_list, session);

  if (!(endpoint->flags & SECURED)) {
    oc_session_start_event((oc_endpoint_t *)endpoint);
  }

  OC_DBG("recorded new TCP session");

  return 0;
}

static void
free_tcp_session(tcp_session_t *session)
{
  oc_session_end_event(&session->endpoint);

  FD_CLR(session->sock, &session->dev->rfds);

  close(session->sock);
  ssize_t len = 0;
  do {
    uint8_t dummy_value = 0xef;
    len = write(session->dev->tcp.connect_pipe[1], &dummy_value, 1);
  } while (len == -1 && errno == EINTR);


  oc_list_remove(session_list, session);
  oc_memb_free(&tcp_session_s, session);

  OC_DBG("freed TCP session");
}

/**
 * Find the available sessions on an oc_list and return a free session
 */
static tcp_session_t *
get_ready_to_read_session(fd_set *setfds)
{
  tcp_session_t *session = oc_list_head(session_list);
  while (session != NULL && !FD_ISSET(session->sock, setfds)) {
    session = session->next;
  }

  if (!session) {
    OC_ERR("could not find any open ready-to-read session");
    return NULL;
  }
  return session;
}

static int
accept_new_session(ip_context_t *dev, int fd, fd_set *setfds,
                   oc_endpoint_t *endpoint)
{
  struct sockaddr_storage receive_from;
  socklen_t receive_len = sizeof(receive_from);

  int new_socket = accept(fd, (struct sockaddr *)&receive_from, &receive_len);
  if (new_socket < 0) {
    OC_ERR("failed to accept incoming TCP connection");
    return -1;
  }
  OC_DBG("accepted incomming TCP connection");

  if (endpoint->flags & IPV6) {
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receive_from;
    memcpy(endpoint->addr.ipv6.address, r->sin6_addr.s6_addr,
           sizeof(r->sin6_addr.s6_addr));
    endpoint->addr.ipv6.scope = r->sin6_scope_id;
    endpoint->addr.ipv6.port = ntohs(r->sin6_port);
#ifdef OC_IPV4
  } else if (endpoint->flags & IPV4) {
    struct sockaddr_in *r = (struct sockaddr_in *)&receive_from;
    memcpy(endpoint->addr.ipv4.address, &r->sin_addr.s_addr,
           sizeof(r->sin_addr.s_addr));
    endpoint->addr.ipv4.port = ntohs(r->sin_port);
#endif /* !OC_IPV4 */
  }

  FD_CLR(fd, setfds);

  if (add_new_session(new_socket, dev, endpoint, CSM_NONE) < 0) {
    OC_ERR("could not record new TCP session");
    close(new_socket);
    return -1;
  }

  FD_SET(new_socket, &dev->rfds);

  return 0;
}

static tcp_session_t *
find_session_by_endpoint(oc_endpoint_t *endpoint)
{
  tcp_session_t *session = oc_list_head(session_list);
  while (session != NULL &&
         oc_endpoint_compare(&session->endpoint, endpoint) != 0) {
    session = session->next;
  }

  if (!session) {
#ifdef OC_DEBUG
    PRINT("could not find ongoing TCP session for endpoint:");
    PRINTipaddr(*endpoint);
    PRINT("\n");
#endif /* OC_DEBUG */
    return NULL;
  }
#ifdef OC_DEBUG
  PRINT("found TCP session for endpoint:");
  PRINTipaddr(*endpoint);
  PRINT("\n");
#endif /* OC_DEBUG */
  return session;
}

static size_t
get_total_length_from_header(oc_message_t *message, oc_endpoint_t *endpoint)
{
  size_t total_length = 0;
  if (endpoint->flags & SECURED) {
    //[3][4] bytes in tls header are tls payload length
    total_length =
      TLS_HEADER_SIZE + (size_t)((message->data[3] << 8) | message->data[4]);
  } else {
    total_length = coap_tcp_get_packet_size(message->data);
  }

  return total_length;
}

static int
get_session_socket(oc_endpoint_t *endpoint)
{
  int sock = -1;
  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (!session) {
    return -1;
  }

  sock = session->sock;
  return sock;
}

/**
 *  Open a socket connection
 */
static int
connect_nonb(int sockfd, const struct sockaddr *r, int r_len, int nsec)
{
  int flags, n, error;
  socklen_t len;
  fd_set rset, wset;
  struct timeval tval;

  flags = fcntl(sockfd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  error = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
  if (error < 0) {
    return -1;
  }

  error = 0;
  if ((n = connect(sockfd, (struct sockaddr *)r, r_len)) < 0) {
    if (errno != EINPROGRESS)
      return -1;
  }

  /**< Do whatever we want while the connect is taking place. */
  if (n == 0) {
    goto done;                                                  /**< connect completed immediately */
  }

  FD_ZERO(&rset);
  FD_SET(sockfd, &rset);
  wset = rset;
  tval.tv_sec = nsec;
  tval.tv_usec = 0;

  if ((n = select(sockfd + 1, &rset, &wset, NULL, nsec ? &tval : NULL)) == 0) {
                    
    errno = ETIMEDOUT;                                          /**< timeout */
    return -1;
  }

  if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
    len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
      return -1; 
  } else {
    OC_DBG("select error: sockfd not set");
    return -1;
  }

done:
  if (error < 0) {
    close(sockfd);                                                      /**< just in case */
    errno = error;
    return -1;
  } else {
    error = fcntl(sockfd, F_SETFL, flags);                              /**< restore file status flags */
    if (error < 0) {
      return -1;
    }
  }
  return 0;
}


static int
initiate_new_session(ip_context_t *dev, oc_endpoint_t *endpoint,
                     const struct sockaddr_storage *receiver)
{
  int sock = -1;
  uint8_t retry_cnt = 0;

  while (retry_cnt < LIMIT_RETRY_CONNECT) {
    if (endpoint->flags & IPV6) {
      sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef OC_IPV4
    } else if (endpoint->flags & IPV4) {
      sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
    }

    if (sock < 0) {
      OC_ERR("could not create socket for new TCP session");
      return -1;
    }

    socklen_t receiver_size = sizeof(*receiver);
    int ret = 0;
    if ((ret = connect_nonb(sock, (struct sockaddr *)receiver, receiver_size,
                            TCP_CONNECT_TIMEOUT)) == 0) {
      break;
    }

    close(sock);
    retry_cnt++;
    OC_DBG("connect fail with %d. retry(%d)", ret, retry_cnt);
  }

  if (retry_cnt >= LIMIT_RETRY_CONNECT) {
    OC_ERR("could not initiate TCP connection");
    return -1;
  }

  OC_DBG("successfully initiated TCP connection");

  if (add_new_session(sock, dev, endpoint, CSM_SENT) < 0) {
    OC_ERR("could not record new TCP session");
    close(sock);
    return -1;
  }

  FD_SET(sock, &dev->rfds);

  OC_DBG("signaled network event thread to monitor the newly added session\n");

  return sock;
}


int
oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                   const struct sockaddr_storage *receiver)
{
  pthread_mutex_lock(&dev->tcp.mutex);
  int send_sock = get_session_socket(&message->endpoint);

  size_t bytes_sent = 0;
  if (send_sock < 0) {
    if ((send_sock = initiate_new_session(dev, &message->endpoint, receiver)) <
        0) {
      OC_ERR("could not initiate new TCP session");
      goto oc_tcp_send_buffer_done;
    }
  }

  do {
    ssize_t send_len = send(send_sock, message->data + bytes_sent,
                            message->length - bytes_sent, 0);
    if (send_len < 0) {
      OC_WRN("send() returned errno %d", errno);
      goto oc_tcp_send_buffer_done;
    }
    bytes_sent += send_len;
  } while (bytes_sent < message->length);

  OC_DBG("Sent %d bytes", bytes_sent);
oc_tcp_send_buffer_done:
  pthread_mutex_unlock(&dev->tcp.mutex);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}


adapter_receive_state_t
oc_tcp_receive_message(ip_context_t *dev, fd_set *fds, oc_message_t *message)
{
  pthread_mutex_lock(&dev->tcp.mutex);

#define ret_with_code(status)                                                  \
  ret = status;                                                                \
  goto oc_tcp_receive_message_done

  adapter_receive_state_t ret = ADAPTER_STATUS_ERROR;
  message->endpoint.device = dev->device;

  if (FD_ISSET(dev->tcp.server_sock, fds)) {
    message->endpoint.flags = IPV6 | TCP;
    if (accept_new_session(dev, dev->tcp.server_sock, fds, &message->endpoint) <
        0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#ifdef OC_SECURITY
  } else if (FD_ISSET(dev->tcp.secure_sock, fds)) {
    message->endpoint.flags = IPV6 | SECURED | TCP;
    if (accept_new_session(dev, dev->tcp.secure_sock, fds, &message->endpoint) <
        0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  } else if (FD_ISSET(dev->tcp.server4_sock, fds)) {
    message->endpoint.flags = IPV4 | TCP;
    if (accept_new_session(dev, dev->tcp.server4_sock, fds,
                           &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#ifdef OC_SECURITY
  } else if (FD_ISSET(dev->tcp.secure4_sock, fds)) {
    message->endpoint.flags = IPV4 | SECURED | TCP;
    if (accept_new_session(dev, dev->tcp.secure4_sock, fds,
                           &message->endpoint) < 0) {
      OC_ERR("accept new session fail");
      ret_with_code(ADAPTER_STATUS_ERROR);
    }
    ret_with_code(ADAPTER_STATUS_ACCEPT);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  } 
  // find session.
  tcp_session_t *session = get_ready_to_read_session(fds);
  if (!session) {
    OC_DBG("could not find TCP session socket in fd set");
    ret_with_code(ADAPTER_STATUS_NONE);
  }

  // receive message.
  size_t total_length = 0;
  size_t want_read = DEFAULT_RECEIVE_SIZE;
  message->length = 0;
  do {
    int count =
      recv(session->sock, message->data + message->length, want_read, 0);
    if (count < 0) {
      OC_ERR("recv error! %d", errno);

      free_tcp_session(session);

      ret_with_code(ADAPTER_STATUS_ERROR);
    } else if (count == 0) {
      OC_DBG("peer closed TCP session\n");

      free_tcp_session(session);

      ret_with_code(ADAPTER_STATUS_NONE);
    }

    OC_DBG("recv(): %d bytes.", count);
    message->length += (size_t)count;
    want_read -= (size_t)count;

    if (total_length == 0) {
      total_length = get_total_length_from_header(message, &session->endpoint);
      if (total_length >
          (unsigned)(OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE)) {
        OC_ERR("total receive length(%zd) is bigger than max pdu size(%ld)",
               total_length, (OC_MAX_APP_DATA_SIZE + COAP_MAX_HEADER_SIZE));
        OC_ERR("It may occur buffer overflow.");
        ret_with_code(ADAPTER_STATUS_ERROR);
      }
      OC_DBG("tcp packet total length : %zd bytes.", total_length);

      want_read = total_length - (size_t)count;
    }
  } while (total_length > message->length);

  memcpy(&message->endpoint, &session->endpoint, sizeof(oc_endpoint_t));
#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
    message->encrypted = 1;
  }
#endif /* OC_SECURITY */

  FD_CLR(session->sock, fds);
  ret = ADAPTER_STATUS_RECEIVE;

oc_tcp_receive_message_done:
  pthread_mutex_unlock(&dev->tcp.mutex);
#undef ret_with_code
  return ret;
}


static int
tcp_connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing TCP adapter IPv4 for device %d", dev->device);

  memset(&dev->tcp.server4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *l = (struct sockaddr_in *)&dev->tcp.server4;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  l->sin_port = 0;

#ifdef OC_SECURITY
  memset(&dev->tcp.secure4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sm = (struct sockaddr_in *)&dev->tcp.secure4;
  sm->sin_family = AF_INET;
  sm->sin_addr.s_addr = INADDR_ANY;
  sm->sin_port = 0;
#endif /* OC_SECURITY */

  dev->tcp.server4_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (dev->tcp.server4_sock < 0) {
    OC_ERR("creating TCP server socket");
    return -1;
  }

#ifdef OC_SECURITY
  dev->tcp.secure4_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.secure4_sock < 0) {
    OC_ERR("creating TCP secure socket");
    return -1;
  }
#endif /* OC_SECURITY */

  if (configure_tcp_socket(dev->tcp.server4_sock, &dev->tcp.server4) < 0) {
    OC_ERR("set socket option in server socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.server4_sock, &dev->tcp.server4) < 0) {
    OC_ERR("get port for server socket");
    return -1;
  }
  dev->tcp.port4 = ntohs(((struct sockaddr_in *)&dev->tcp.server4)->sin_port);

#ifdef OC_SECURITY
  if (configure_tcp_socket(dev->tcp.secure4_sock, &dev->tcp.secure4) < 0) {
    OC_ERR("set socket option in secure socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.secure4_sock, &dev->tcp.secure4) < 0) {
    OC_ERR("get port for secure socket");
    return -1;
  }
  dev->tcp.tls4_port =
    ntohs(((struct sockaddr_in *)&dev->tcp.secure4)->sin_port);
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized TCP adapter IPv4 for device %d",
         dev->device);

  return 0;
}


int
oc_tcp_connectivity_init(ip_context_t *dev)
{
  OC_DBG("Initializing TCP adapter for device %d", dev->device);

  if (pthread_mutex_init(&dev->tcp.mutex, NULL) != 0) {
    oc_abort("error initializing TCP adapter mutex");
  }

  memset(&dev->tcp.server, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->tcp.server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&dev->tcp.secure, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&dev->tcp.secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_addr = in6addr_any;
  sm->sin6_port = 0;
#endif /* OC_SECURITY */

  dev->tcp.server_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

  if (dev->tcp.server_sock < 0) {
    OC_ERR("creating TCP server socket");
    return -1;
  }

#ifdef OC_SECURITY
  dev->tcp.secure_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (dev->tcp.secure_sock < 0) {
    OC_ERR("creating TCP secure socket");
    return -1;
  }
#endif /* OC_SECURITY */

  if (configure_tcp_socket(dev->tcp.server_sock, &dev->tcp.server) < 0) {
    OC_ERR("set socket option in server socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.server_sock, &dev->tcp.server) < 0) {
    OC_ERR("get port for server socket");
    return -1;
  }
  dev->tcp.port = ntohs(((struct sockaddr_in *)&dev->tcp.server)->sin_port);

#ifdef OC_SECURITY
  if (configure_tcp_socket(dev->tcp.secure_sock, &dev->tcp.secure) < 0) {
    OC_ERR("set socket option in secure socket");
    return -1;
  }

  if (get_assigned_tcp_port(dev->tcp.secure_sock, &dev->tcp.secure) < 0) {
    OC_ERR("get port for secure socket");
    return -1;
  }
  dev->tcp.tls_port = ntohs(((struct sockaddr_in *)&dev->tcp.secure)->sin_port);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  if (tcp_connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4 for TCP");
  }
#endif /* OC_IPV4 */


  OC_DBG("=======tcp port info.========");
  OC_DBG("  ipv6 port   : %u", dev->tcp.port);
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %u", dev->tcp.tls_port);
#endif
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %u", dev->tcp.port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->tcp.tls4_port);
#endif
#endif

  OC_DBG("Successfully initialized TCP adapter for device %d", dev->device);

  return 0;
}


void
oc_tcp_end_session(ip_context_t *dev, oc_endpoint_t *endpoint)
{
  pthread_mutex_lock(&dev->tcp.mutex);
  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (session) {
    free_tcp_session(session);
  }
  pthread_mutex_unlock(&dev->tcp.mutex);
}


void
oc_connectivity_end_session(oc_endpoint_t *endpoint)
{
  if (endpoint->flags & TCP) {
    ip_context_t *dev = get_ip_context_for_device(endpoint->device);
    if (dev) {
      oc_tcp_end_session(dev, endpoint);
    }
  }
}


tcp_csm_state_t
oc_tcp_get_csm_state(oc_endpoint_t *endpoint)
{
  if (!endpoint) {
    return CSM_ERROR;
  }

  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (!session) {
    return CSM_NONE;
  }
  return session->csm_state;
}


int
oc_tcp_update_csm_state(oc_endpoint_t *endpoint, tcp_csm_state_t csm)
{
  if (!endpoint) {
    return -1;
  }

  tcp_session_t *session = find_session_by_endpoint(endpoint);
  if (!session) {
    return -1;
  }

  session->csm_state = csm;
  return 0;
}



/**********************************************************************
 *************************** End of TCP support************************
**********************************************************************/
#ifdef OC_IPV4

/**
 *  Add a socket to a multicast group on IPV4
 */ 
static int add_mcast_sock_to_ipv4_mcast_group(int mcast_sock,
                                              const struct in_addr *local,
                                              int interface_index) {
    struct ip_mreq imreq = { 0 };
    int err = 0;
    // Configure source interface
    memset(&imreq, 0, sizeof(struct ip_mreq));
    tcpip_adapter_ip_info_t ip_info = { 0 };
    err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info);
    if (err != ESP_OK) {
        print_error("get ip4 ret:%d\n", err);
    }

    inet_addr_from_ipaddr(&imreq.imr_interface, &ip_info.ip);
    imreq.imr_multiaddr.s_addr = htonl(ALL_COAP_NODES_V4);
    ESP_LOGI(TAG, "Configured IPV4 Multicast address %s", inet_ntoa(imreq.imr_multiaddr.s_addr));

    if (!IP_MULTICAST(ntohl(imreq.imr_multiaddr.s_addr))) {
        print_error("not a valid multicast address");
    }

    err = setsockopt(mcast_sock, IPPROTO_IP, IP_MULTICAST_IF, &imreq.imr_interface, sizeof(struct in_addr));
    if (err < 0) {
        print_error("setsockopt IP_MULTICAST_IF ret:%d", err);
    }

#ifdef OC_LEAVE_GROUP
    err = setsockopt(mcast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &imreq, sizeof(struct ip_mreq));
    if (err < 0) {
        print_error("setsockopt IP_DROP_MEMBERSHIP ret:%d", err);
    }
#endif

    err = setsockopt(mcast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,  &imreq, sizeof(struct ip_mreq));
    if (err < 0) {
        print_error("setsockopt IP_ADD_MEMBERSHIP ret:%d", err);
    }
  return 0;
}
#endif /* OC_IPV4 */

/**
 *  Add a socket to a multicast group on IPV6
 */ 
static int add_mcast_sock_to_ipv6_mcast_group(int mcast_sock, int interface_index)
{
    int err = 0;
    struct ip6_mreq v6imreq = { 0 };
    struct ip6_addr if_ipaddr = { 0 };
    err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr);
    if (err != ESP_OK) {
        print_error("got ip6 addr ret:%d\n", err);
    }
                                                                                  /**< Link-local scope */
    memset(&v6imreq, 0, sizeof(struct ip6_mreq));
                                                                                  /**< interface */
     inet6_addr_from_ip6addr(&v6imreq.ipv6mr_interface, &if_ipaddr);
                                                                                  /**< copy ipv6 */
     memcpy(v6imreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_LL, 16);
     err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &v6imreq.ipv6mr_interface, sizeof(struct in6_addr));
     if (err < 0) {
         print_error("setsockopt IPV6_MULTICAST_IF ret:%d\n", err);
     }

#ifdef OC_LEAVE_GROUP
    err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &v6imreq, sizeof(struct ip6_mreq));
    if (err < 0) {
        print_error("set IPV6_DROP_MEMBERSHIP ret:%d\n",err);
    }
#endif
    err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &v6imreq, sizeof(struct ip6_mreq));
    if (err < 0) {
        print_error("set IPV6_ADD_MEMBERSHIP ret:%d\n",err);
    }

                                                                                  /**< Realm-local scope */
    memset(&v6imreq, 0, sizeof(struct ip6_mreq));
    inet6_addr_from_ip6addr(&v6imreq.ipv6mr_interface, &if_ipaddr);
    memcpy(v6imreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_RL, 16);
    ESP_LOGI(TAG, "Configured IPV6 Multicast address %s", inet_ntoa(v6imreq.ipv6mr_multiaddr.s6_addr));

#ifdef OC_LEAVE_GROUP
    err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &v6imreq, sizeof(struct ip6_mreq));
    if (err < 0) {
        print_error("set IPV6_DROP_MEMBERSHIP ret:%d\n",err);
    }
#endif
    err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &v6imreq, sizeof(struct ip6_mreq));
    if (err < 0) {
        print_error("set IPV6_ADD_MEMBERSHIP ret:%d\n",err);
    }

                                                                                  /**< Site-local scope */
    memset(&v6imreq, 0, sizeof(struct ip6_mreq));
    inet6_addr_from_ip6addr(&v6imreq.ipv6mr_interface, &if_ipaddr);
    memcpy(v6imreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_SL, 16);

#ifdef OC_LEAVE_GROUP
    err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &v6imreq, sizeof(struct ip6_mreq));
    if (err < 0) {
        print_error("set IPV6_DROP_MEMBERSHIP ret:%d\n",err);
    }
#endif

    err = setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &v6imreq, sizeof(struct ip6_mreq));
    if (err < 0) {
        print_error("set IPV6_ADD_MEMBERSHIP ret:%d\n",err);
    }

  return 0;
}

/**
 * 
 */ 
static int configure_mcast_socket(int mcast_sock, int sa_family) {
    int ret = 0;
    
    if (sa_family == AF_INET6) {                                    /**< Accordingly handle IPv6/IPv4 addresses */    
        ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, NULL);
    }
#ifdef OC_IPV4
    else if (sa_family == AF_INET) {
      ret += add_mcast_sock_to_ipv4_mcast_group(mcast_sock, NULL,
                                                NULL);
    }
#endif                                                              /* OC_IPV4 */

  return ret;
}

/**
 * 
 */ 
static void 
*network_event_thread(void *data) {
  struct sockaddr_storage client;
  memset(&client, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *c = (struct sockaddr_in6 *)&client;
  socklen_t len = sizeof(client);

#ifdef OC_IPV4
  struct sockaddr_in *c4 = (struct sockaddr_in *)&client;
#endif

  ip_context_t *dev = (ip_context_t *)data;

  fd_set rfds, setfds;
  FD_ZERO(&dev->rfds);
  FD_ZERO(&rfds);
  FD_SET(dev->server_sock, &rfds);
  FD_SET(dev->mcast_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure_sock, &rfds);
#endif /* OC_SECURITY */

#ifdef OC_IPV4
  FD_SET(dev->server4_sock, &rfds);
  FD_SET(dev->mcast4_sock, &rfds);
#ifdef OC_SECURITY
  FD_SET(dev->secure4_sock, &rfds);
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
#ifdef OC_TCP
  oc_tcp_add_socks_to_fd_set(dev);
#endif 
  int i, n;

  while (dev->terminate != 1) {
    len = sizeof(client);
    setfds = rfds;
#ifdef OC_IPV4
    int maxfd = (dev->server4_sock > dev->mcast4_sock) ? dev->server4_sock : dev->mcast4_sock;
#else
    int maxfd = (dev->server_sock > dev->mcast_sock) ? dev->server_sock : dev->mcast_sock;
#endif
    n = select(maxfd + 1, &setfds, NULL, NULL, NULL);
    for (i = 0; i < n; i++) {
      len = sizeof(client);
      oc_message_t *message = oc_allocate_message();

      if (!message) {
        break;
      }

      if (FD_ISSET(dev->server_sock, &setfds)) {
        int count = recvfrom(dev->server_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = (size_t)count;
        message->endpoint.flags = IPV6;
        message->endpoint.device = dev->device;
        FD_CLR(dev->server_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(dev->mcast_sock, &setfds)) {
        int count = recvfrom(dev->mcast_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = (size_t)count;
        message->endpoint.flags = IPV6 | MULTICAST;
        message->endpoint.device = dev->device;
        FD_CLR(dev->mcast_sock, &setfds);
        goto common;
      }

#ifdef OC_IPV4
      if (FD_ISSET(dev->server4_sock, &setfds)) {
        int count = recvfrom(dev->server4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = (size_t)count;
        message->endpoint.flags = IPV4;
        message->endpoint.device = dev->device;
        FD_CLR(dev->server4_sock, &setfds);
        goto common;
      }

      if (FD_ISSET(dev->mcast4_sock, &setfds)) {
        int count = recvfrom(dev->mcast4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = (size_t)count;
        message->endpoint.flags = IPV4 | MULTICAST;
        message->endpoint.device = dev->device;
        FD_CLR(dev->mcast4_sock, &setfds);
        goto common;
      }
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
      if (FD_ISSET(dev->secure_sock, &setfds)) {
        int count = recvfrom(dev->secure_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = (size_t)count;
        message->endpoint.flags = IPV6 | SECURED;
        message->endpoint.device = dev->device;
        message->encrypted = 1;
        FD_CLR(dev->secure_sock, &setfds);
      }
#ifdef OC_IPV4
      if (FD_ISSET(dev->secure4_sock, &setfds)) {
        int count = recvfrom(dev->secure4_sock, message->data, OC_PDU_SIZE, 0,
                             (struct sockaddr *)&client, &len);
        if (count < 0) {
          oc_message_unref(message);
          continue;
        }
        message->length = (size_t)count;
        message->endpoint.flags = IPV4 | SECURED;
        message->endpoint.device = dev->device;
        message->encrypted = 1;
        FD_CLR(dev->secure4_sock, &setfds);
      }
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */
#ifdef OC_TCP
      if (oc_tcp_receive_message(dev, &setfds, message) ==
          ADAPTER_STATUS_RECEIVE) {
        goto common;
      }
#endif /* OC_TCP */

    common:
#ifdef OC_IPV4
      if (message->endpoint.flags & IPV4) {
        memcpy(message->endpoint.addr.ipv4.address, &c4->sin_addr.s_addr,
               sizeof(c4->sin_addr.s_addr));
        message->endpoint.addr.ipv4.port = ntohs(c4->sin_port);
      } else if (message->endpoint.flags & IPV6) {
#else  /* OC_IPV4 */
      if (message->endpoint.flags & IPV6) {
#endif /* !OC_IPV4 */
        memcpy(message->endpoint.addr.ipv6.address, c->sin6_addr.s6_addr,
               sizeof(c->sin6_addr.s6_addr));
        message->endpoint.addr.ipv6.scope = IPADDR_ANY;
message->endpoint.addr.ipv6.port = ntohs(c->sin6_port);
      }

#ifdef OC_DEBUG
      PRINT("Incoming message of size %d bytes from ", message->length);
      PRINTipaddr(message->endpoint);
      PRINT("\n\n");
#endif /* OC_DEBUG */

      oc_network_event(message);
    }
  }
  vTaskDelete(NULL);
  return NULL;
}


oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
    (void)device;
    ip_context_t *dev = get_ip_context_for_device(device);
    if (!dev) {
      return NULL;
    }
    oc_init_endpoint_list();
    oc_endpoint_t ep;
    oc_endpoint_t sec;
    memset(&sec,0,sizeof(oc_endpoint_t));
    memset(&ep, 0, sizeof(oc_endpoint_t));
    int err = 0;
#ifdef OC_IPV4
    ep.flags = IPV4;
    ep.addr.ipv4.port = OCF_PORT_UNSECURED;
    tcpip_adapter_ip_info_t sta_ip;
    err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &sta_ip);
    if (err != ESP_OK) {
        print_error("get ipv4 failed,ret:%d\n", err);
    }
    memcpy(ep.addr.ipv4.address, &sta_ip.ip, 4);
#ifdef OC_SECURITY
    ep.flags |= SECURED;
#endif
#else                                                                         // IPv6
    ep.flags = IPV6;
    ep.addr.ipv6.port = OCF_PORT_UNSECURED;
    struct ip6_addr if_ipaddr = { 0 };
    err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr);
    if (err != ESP_OK) {
        print_error("get ipv6 failed,ret:%d\n", err);
    }
    memcpy(ep.addr.ipv6.address, if_ipaddr.addr, 16);
    ep.device = 0;
    oc_add_endpoint_to_list(&ep);
#endif
#ifdef OC_SECURITY
#ifdef OC_IPV4
    sec.flags = IPV4;
    sec.addr.ipv4.port = OCF_PORT_SECURE;
    tcpip_adapter_ip_info_t sta_i;
    err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &sta_i);
    if (err != ESP_OK) {
        print_error("get ipv4 failed,ret:%d\n", err);
    }
    memcpy(sec.addr.ipv4.address, &sta_i.ip, 4);
#else   // IPv6
    sec.flags = IPV6;
    sec.addr.ipv6.port = OCF_PORT_SECURE;
    struct ip6_addr if_ipadd = { 0 };
    err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipadd);
    if (err != ESP_OK) {
        print_error("get ipv6 failed,ret:%d\n", err);
    }
    memcpy(sec.addr.ipv6.address, if_ipadd.addr, 16);
#endif
    sec.flags |= SECURED;
    sec.device = 0;
    oc_add_endpoint_to_list(&sec);
#endif
#ifdef OC_TCP
    oc_endpoint_t sectcp;
    memset(&sectcp,0,sizeof(oc_endpoint_t));
#ifdef OC_IPV4
    sectcp.flags = IPV4;
    sectcp.addr.ipv4.port = OCF_PORT_TCP;
    tcpip_adapter_ip_info_t sta_iptcp;
    err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &sta_iptcp);
    if (err != ESP_OK) {
        print_error("get ipv4 failed,ret:%d\n", err);
    }
    memcpy(sectcp.addr.ipv4.address, &sta_iptcp.ip, 4);
#ifdef OC_SECURITY
    sectcp.flags |= SECURED;
#endif
#else
    sectcp.flags = IPV6;
    sectcp.addr.ipv6.port = OCF_PORT_TCP+1;
    struct ip6_addr if_ipaddtcp = { 0 };
    err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddtcp);
    if (err != ESP_OK) {
        print_error("get ipv6 failed,ret:%d\n", err);
    }
    memcpy(sectcp.addr.ipv6.address, if_ipaddtcp.addr, 16);
#endif
    sectcp.flags |= TCP;
    sectcp.device = 0;
    oc_add_endpoint_to_list(&sectcp);
#endif

#ifdef OC_TCP
    oc_endpoint_t nosectcp;
    memset(&nosectcp,0,sizeof(oc_endpoint_t));
#ifdef OC_IPV4
    nosectcp.flags = IPV4;
    nosectcp.addr.ipv4.port = OC_PORT_TCP_UNSECURE;
    tcpip_adapter_ip_info_t sta_iptcpno;
    err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &sta_iptcpno);
    if (err != ESP_OK) {
        print_error("get ipv4 failed,ret:%d\n", err);
    }
    memcpy(nosectcp.addr.ipv4.address, &sta_iptcpno.ip, 4);
#else
    nosectcp.flags = IPV6;
    nosectcp.addr.ipv6.port = OC_PORT_TCP_UNSECURE;
    struct ip6_addr if_ipaddtcpno = { 0 };
    err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddtcpno);
    if (err != ESP_OK) {
        print_error("get ipv6 failed,ret:%d\n", err);
    }
    memcpy(nosectcp.addr.ipv6.address, if_ipaddtcpno.addr, 16);
#endif
    nosectcp.flags |= TCP;
    nosectcp.device = 0;
    oc_add_endpoint_to_list(&nosectcp);
#endif
    return oc_get_endpoint_list();
}



int oc_send_buffer(oc_message_t *message) {
#ifdef OC_DEBUG
  PRINT("Outgoing message of size %d bytes to ", message->length);
  PRINTipaddr(message->endpoint);
  PRINT("\n\n");
#endif /* OC_DEBUG */

  struct sockaddr_storage receiver;
  memset(&receiver, 0, sizeof(struct sockaddr_storage));
#ifdef OC_IPV4
  if (message->endpoint.flags & IPV4) {
    struct sockaddr_in *r = (struct sockaddr_in *)&receiver;
    memcpy(&r->sin_addr.s_addr, message->endpoint.addr.ipv4.address,
           sizeof(r->sin_addr.s_addr));
    r->sin_family = AF_INET;
    r->sin_port = htons(message->endpoint.addr.ipv4.port);
  } else {
#else
  {
#endif
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
    memcpy(r->sin6_addr.s6_addr, message->endpoint.addr.ipv6.address,
           sizeof(r->sin6_addr.s6_addr));
    r->sin6_family = AF_INET6;
    r->sin6_port = htons(message->endpoint.addr.ipv6.port);
    r->sin6_scope_id = IPADDR_ANY;
  }
  int send_sock = -1;
  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);
#ifdef OC_TCP
  if (message->endpoint.flags & TCP) {
    return oc_tcp_send_buffer(dev, message, &receiver);
  }
#endif /* OC_TCP */

#ifdef OC_SECURITY
  if (message->endpoint.flags & SECURED) {
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
      send_sock = dev->secure4_sock;
    } else {
      send_sock = dev->secure_sock;
    }
#else  /* OC_IPV4 */
    send_sock = dev->secure_sock;
#endif /* !OC_IPV4 */
  } else
#endif /* OC_SECURITY */
#ifdef OC_IPV4
    if (message->endpoint.flags & IPV4) {
    send_sock = dev->server4_sock;
  } else {
    send_sock = dev->server_sock;
  }
#else  /* OC_IPV4 */
  {
    send_sock = dev->server_sock;
  }
#endif /* !OC_IPV4 */

  int bytes_sent = 0, x;
  while (bytes_sent < (int)message->length) {
    x = sendto(send_sock, message->data + bytes_sent,
        message->length - bytes_sent, 0, (struct sockaddr *)&receiver,
        sizeof(receiver));
    if (x < 0) {
      OC_WRN("sendto() returned errno %d\n", errno);
      return;
    }
    bytes_sent += x;
  }
  OC_DBG("Sent %d bytes\n", bytes_sent);
}



void oc_send_discovery_request(oc_message_t *message)
{
  ip_context_t *dev = get_ip_context_for_device(message->endpoint.device);
  struct in6_addr if_inaddr = { 0 };
  struct ip6_addr if_ipaddr = { 0 };
  int err = 0;
#ifndef OC_IPV4
    err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr);
    inet6_addr_from_ip6addr(&if_inaddr, &if_ipaddr);
    if (err != ESP_OK) {
        print_error("tcpip_adapter_get_ip6_linklocal ret:%d\n", err);
    }
    // Assign the multicast source interface, via its IP
    err = setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &if_inaddr, sizeof(struct in6_addr));
    if (err < 0) {
        print_error("set opt ret:%d\n", err);
    }
    oc_send_buffer(message);
#else
  tcpip_adapter_ip_info_t ip_info = { 0 };
  struct in_addr iaddr = { 0 };
  err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info);
  if (err != ESP_OK) {
      print_error("get ip ret:%d\n", err);
  }
  inet_addr_from_ipaddr(&iaddr, &ip_info.ip);

  /** Assign the IPv4 multicast source interface, via its IP
   (only necessary if this socket is IPV4 only) */
  err = setsockopt(dev->server4_sock, IPPROTO_IP, IP_MULTICAST_IF, &iaddr, sizeof(struct in_addr));
  if (err < 0) {
      print_error("set opt ret:%d\n", err);
  }
  oc_send_buffer(message);
#endif
}

#ifdef OC_IPV4
static int
connectivity_ipv4_init(ip_context_t *dev)
{
  OC_DBG("Initializing IPv4 connectivity for device %d\n", dev->device);
  memset(&dev->mcast4, 0, sizeof(struct sockaddr_storage));
  memset(&dev->server4, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in *m = (struct sockaddr_in *)&dev->mcast4;
  m->sin_family = AF_INET;
  m->sin_port = htons(OCF_PORT_UNSECURED);
  m->sin_addr.s_addr = INADDR_ANY;

  struct sockaddr_in *l = (struct sockaddr_in *)&dev->server4;
  l->sin_family = AF_INET;
  l->sin_addr.s_addr = INADDR_ANY;
  int err = 0;
  tcpip_adapter_ip_info_t ip_info = { 0 };
  err = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info);
  if (err != ESP_OK) {
      print_error("get ip4 ret:%d\n", err);
  }
  inet_addr_from_ipaddr(&l->sin_addr, &ip_info.ip);
  l->sin_port = 0;

#ifdef OC_SECURITY
  memset(&dev->secure4, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in *sm = (struct sockaddr_in *)&dev->secure4;
  sm->sin_family = AF_INET;
  sm->sin_port = htons(OCF_PORT_SECURE);
//  sm->sin_port = 0;
  sm->sin_addr.s_addr = INADDR_ANY;

  dev->secure4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure4_sock < 0) {
    OC_ERR("error creating secure IPv4 socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  dev->server4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast4_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server4_sock < 0 || dev->mcast4_sock < 0) {
    OC_ERR("creating IPv4 server sockets\n");
    return -1;
  }

  int on = 1;
  if (setsockopt(dev->server4_sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting pktinfo IPv4 option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->server4_sock, SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting reuseaddr option %d", errno);
    return -1;
  }

  if (bind(dev->server4_sock, (struct sockaddr *)&dev->server4,
           sizeof(dev->server4)) == -1) {
    OC_ERR("binding server4 socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server4);
  if (getsockname(dev->server4_sock, (struct sockaddr *)&dev->server4,
                  &socklen) == -1) {
    OC_ERR("obtaining server4 socket information %d\n", errno);
    return -1;
  }

  dev->port4 = ntohs(l->sin_port);

  if (configure_mcast_socket(dev->mcast4_sock, AF_INET) < 0) {
    return -1;
  }

  int reuse = 1;
  if (setsockopt(dev->mcast4_sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) ==
      -1) {
    OC_ERR("setting pktinfo IPv4 option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->mcast4_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }
  if (bind(dev->mcast4_sock, (struct sockaddr *)&dev->mcast4,
           sizeof(dev->mcast4)) == -1) {
    OC_ERR("binding mcast IPv4 socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure4_sock, IPPROTO_IP, IP_PKTINFO, &reuse, sizeof(reuse)) ==
      -1) {
    OC_ERR("setting pktinfo IPV4 option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->secure4_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr IPv4 option %d\n", errno);
    return -1;
  }

  if (bind(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
           sizeof(dev->secure4)) == -1) {
    OC_ERR("binding IPv4 secure socket %d\n", errno);
    return -1;
  }

  socklen = sizeof(dev->secure4);
  if (getsockname(dev->secure4_sock, (struct sockaddr *)&dev->secure4,
                  &socklen) == -1) {
    OC_ERR("obtaining DTLS4 socket information %d\n", errno);
    return -1;
  }

  dev->dtls4_port = ntohs(sm->sin_port);
#endif /* OC_SECURITY */

  OC_DBG("Successfully initialized IPv4 connectivity for device %d\n",
         dev->device);

  return 0;
}
#endif


int oc_connectivity_init(size_t device) {
  OC_DBG("Initializing connectivity for device %d\n", device);
#ifdef OC_DYNAMIC_ALLOCATION
  ip_context_t *dev = (ip_context_t *)calloc(1, sizeof(ip_context_t));
  if (!dev) {
    oc_abort("Insufficient memory");
  }
  oc_list_add(ip_contexts, dev);
#else                                                             /**< OC_DYNAMIC_ALLOCATION */
  ip_context_t *dev = &devices[device];
#endif                                                            /**< !OC_DYNAMIC_ALLOCATION */
  dev->device = device;
#ifndef OC_IPV4
  dev->device = device;
  OC_LIST_STRUCT_INIT(dev, eps);

  memset(&dev->mcast, 0, sizeof(struct sockaddr_storage));
  memset(&dev->server, 0, sizeof(struct sockaddr_storage));

  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&dev->mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(OCF_PORT_UNSECURED);
  m->sin6_addr = in6addr_any;
  int err = 0;
  struct ip6_addr if_ipaddr = { 0 };

  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->server;
  l->sin6_family = AF_INET6;

  err = tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr);
  if (err != ESP_OK) {
      print_error("get ip6 ret:%d\n", err);
  }
  inet6_addr_from_ip6addr(&l->sin6_addr, &if_ipaddr);

  l->sin6_port = 0;

#ifdef OC_SECURITY
  memset(&dev->secure, 0, sizeof(struct sockaddr_storage));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&dev->secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_port = htons(OCF_PORT_SECURE);                               /**< Setting Port number for IPV6 CoAps*/
  sm->sin6_addr = in6addr_any;
#endif /* OC_SECURITY */

  dev->server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server_sock < 0 || dev->mcast_sock < 0) {
    OC_ERR("creating server sockets\n");
    return -1;
  }

#ifdef OC_SECURITY
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock < 0) {
    OC_ERR("creating secure socket\n");
    return -1;
  }
#endif /* OC_SECURITY */

  int opt = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt,
                 sizeof(opt)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
                 sizeof(opt)) == -1) {
    OC_ERR("setting sock option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) ==
      -1) {
    OC_ERR("setting reuseaddr option %d", errno);
    return -1;
  }
  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == -1) {
    OC_ERR("binding server socket %d\n", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == -1) {
    OC_ERR("obtaining server socket information %d\n", errno);
    return -1;
  }

  dev->port = ntohs(l->sin6_port);

  if (configure_mcast_socket(dev->mcast_sock, AF_INET6) < 0) {
    return -1;
  }

  int reuse = 1;
  if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == -1) {
    OC_ERR("binding mcast socket %d\n", errno);
    return -1;
  }

#ifdef OC_SECURITY
  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d\n", errno);
    return -1;
  }
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) == -1) {
    OC_ERR("setting reuseaddr option %d\n", errno);
    return -1;
  }
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == -1) {
    OC_ERR("binding IPv6 secure socket %d\n", errno);
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == -1) {
    OC_ERR("obtaining secure socket information %d\n", errno);
    return -1;
  }

  dev->dtls_port = ntohs(sm->sin6_port);
#endif /* OC_SECURITY */
#endif

#ifdef OC_TCP
  if(oc_tcp_connectivity_init(dev)!=0){                           /**< Initializing TCP connectivity */
    OC_ERR("Could not initialize TCP\n");
  }
#endif

#ifdef OC_IPV4
  if (connectivity_ipv4_init(dev) != 0) {
    OC_ERR("Could not initialize IPv4\n");
  }
#endif /* OC_IPV4 */

  if (pthread_create(&dev->event_thread, NULL, &network_event_thread, dev) !=
      0) {
    OC_ERR("creating network polling thread\n");
    return -1;
  }

OC_DBG("=======ip port info.========");
  OC_DBG("  ipv6 port   : %u", dev->port);
#ifdef OC_SECURITY
  OC_DBG("  ipv6 secure : %u", dev->dtls_port);
#endif
#ifdef OC_IPV4
  OC_DBG("  ipv4 port   : %u", dev->port4);
#ifdef OC_SECURITY
  OC_DBG("  ipv4 secure : %u", dev->dtls4_port);
#endif
#endif

  OC_DBG("Successfully initialized connectivity for device %d\n", device);

  return 0;
}



void
oc_connectivity_shutdown(size_t device)
{
  ip_context_t *dev = get_ip_context_for_device(device);
  dev->terminate = 1;

  close(dev->server_sock);
  close(dev->mcast_sock);

#ifdef OC_IPV4
  close(dev->server4_sock);
  close(dev->mcast4_sock);
#endif /* OC_IPV4 */

#ifdef OC_SECURITY
  close(dev->secure_sock);
#ifdef OC_IPV4
  close(dev->secure4_sock);
#endif /* OC_IPV4 */
#endif /* OC_SECURITY */

  pthread_cancel(dev->event_thread);
  pthread_join(dev->event_thread, NULL);

#ifdef OC_DYNAMIC_ALLOCATION
  oc_list_remove(ip_contexts, dev);
  free(dev);
#endif /* OC_DYNAMIC_ALLOCATION */

  OC_DBG("oc_connectivity_shutdown for device %d\n", device);
}



