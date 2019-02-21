#ifndef IPCONTEXT_H
#define IPCONTEXT_H

#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include <pthread.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
  ADAPTER_STATUS_NONE = 0, /* Nothing happens */
  ADAPTER_STATUS_ACCEPT,   /* Receiving no meaningful data */
  ADAPTER_STATUS_RECEIVE,  /* Receiving meaningful data */
  ADAPTER_STATUS_ERROR     /* Error */
} adapter_receive_state_t;

#ifdef OC_TCP
/**
 *  Struct designed to allow tcp connection and messages storage 
 */
typedef struct tcp_context_t
{
  struct sockaddr_storage server;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  struct sockaddr_storage secure;
  int secure_sock;
  uint16_t tls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  struct sockaddr_storage server4;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  struct sockaddr_storage secure4;
  int secure4_sock;
  uint16_t tls4_port;
#endif /* OC_SECURITY */
#endif /* OC_IPV4 */
  int connect_pipe[2];
  pthread_mutex_t mutex;
} tcp_context_t;

/**
 *  Keeps session's data on TCP connections 
 * 
 */
typedef struct tcp_session
{
  struct tcp_session *next;           /**< next tcp session */
  ip_context_t *dev;                  /**< device number */
  oc_endpoint_t endpoint;            
  int sock;
  tcp_csm_state_t csm_state;          /**< device number */
} tcp_session_t;

#endif

/**
 *   
 */
typedef struct ip_context_t {
  struct ip_context_t *next;
  OC_LIST_STRUCT(eps);
  struct sockaddr_storage mcast;
  struct sockaddr_storage server;
  int mcast_sock;
  int server_sock;
  uint16_t port;
#ifdef OC_SECURITY
  struct sockaddr_storage secure;
  int secure_sock;
  uint16_t dtls_port;
#endif /* OC_SECURITY */
#ifdef OC_IPV4
  struct sockaddr_storage mcast4;
  struct sockaddr_storage server4;
  int mcast4_sock;
  int server4_sock;
  uint16_t port4;
#ifdef OC_SECURITY
  struct sockaddr_storage secure4;
  int secure4_sock;
  uint16_t dtls4_port;
#endif                                                      /* OC_SECURITY */
#endif                                                      /* OC_IPV4 */
#ifdef OC_TCP
  tcp_context_t tcp;
#endif
  pthread_t event_thread;
  int terminate;
  size_t device;
  fd_set rfds;
  int shutdown_pipe[2];
} ip_context_t;

#endif                                                      /* IPCONTEXT_H */