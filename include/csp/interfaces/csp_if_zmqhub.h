#ifndef CSP_IF_ZMQHUB_H_
#define CSP_IF_ZMQHUB_H_

#include <csp/csp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
   ZMQ interface will connect to this port for publishing (tx) data.
*/
#define CSP_ZMQHUB_DEFAULT_PROXY_SUBSCRIBE_PORT   6000

/**
   ZMQ interface will connect to this port for subscribing (rx) data.
*/
#define CSP_ZMQHUB_DEFAULT_PROXY_PUBLISH_PORT     7000

/**
   Format endpoint connection string for zmq.

   @param[in] host host name of IP.
   @param[in] port IP port
   @param[out] buf user allocated buffer for receiving formatted string.
   @param[in] buf_size size of \a buf.
   @return #CSP_ERR_NONE on succcess.
   @return #CSP_ERR_NOMEM if supplied buffer too small.
*/
int csp_zmqhub_make_endpoint(const char * host, uint16_t port, char * buf, size_t buf_size);

/**
   Setup ZMQ interface
   @param addr only receive messages matching this address (255 means all)
   @param host host name or IP of zmqproxy host.
   @return #CSP_ERR_NONE on succcess - else assert.
*/
int csp_zmqhub_init(uint8_t addr, const char * host);

/**
 * Setup ZMQ interface
 * @param addr only receive messages matching this address (255 means all)
 * @param publisher_endpoint Pointer to string containing zmqproxy publisher endpoint
 * @param subscriber_endpoint Pointer to string containing zmqproxy subscriber endpoint
 * @return CSP_ERR
 */
int csp_zmqhub_init_w_endpoints(uint8_t addr, const char * publisher_url,
                                const char * subscriber_url);

/**
   Setup ZMQ interface
   @param name Name of interface.
   @param rx_filter Rx filter array, use NULL to receive all addresses.
   @param rx_filter_count Number of Rx filters in \a rx_filter.
   @param publisher_endpoint Pointer to string containing zmqproxy publisher endpoint
   @param subscriber_endpoint Pointer to string containing zmqproxy subscriber endpoint
   @param[out] return_interface created ZMQ interface
   @return CSP_ERR
*/
int csp_zmqhub_init_w_name_endpoints_rxfilter(const char * name,
                                              const uint8_t rx_filter[], unsigned int rx_filter_count,
                                              const char * publisher_endpoint,
                                              const char * subscriber_endpoint,
                                              csp_iface_t ** return_interface);

#ifdef __cplusplus
}
#endif
#endif /* CSP_IF_ZMQHUB_H_ */
