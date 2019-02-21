#include "port/oc_connectivity.h"
#include "esp_ipcontext.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/inet.h"

/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
struct in6_pktinfo {
  struct in6_addr ipi6_addr;	/* src/dst IPv6 address */
  unsigned int ipi6_ifindex;	/* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};

int oc_tcp_connectivity_init(ip_context_t *dev);

void oc_tcp_connectivity_shutdown(ip_context_t *dev);

int oc_tcp_send_buffer(ip_context_t *dev, oc_message_t *message,
                       const struct sockaddr_storage *receiver);

void oc_tcp_add_socks_to_fd_set(ip_context_t *dev);

void oc_tcp_set_session_fds(fd_set *fds);

adapter_receive_state_t oc_tcp_receive_message(ip_context_t *dev, fd_set *fds,
                                               oc_message_t *message);
                                               
void oc_tcp_end_session(ip_context_t *dev, oc_endpoint_t *endpoint);

#ifdef __cplusplus
}
#endif