/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <assert.h>

/* CSP includes */
#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_interface.h>
#include <csp/arch/csp_thread.h>
#include <csp/arch/csp_semaphore.h>
#include <csp/interfaces/csp_if_zmqhub.h>
#include <errno.h>

/* ZMQ */
#include <zmq.h>

static void * context;
static void * publisher;
static void * subscriber;
static csp_bin_sem_handle_t tx_wait;

/**
 * Interface transmit function
 * @param packet Packet to transmit
 * @param timeout Timeout in ms
 * @return 1 if packet was successfully transmitted, 0 on error
 */
int csp_zmqhub_tx(csp_iface_t * interface, csp_packet_t * packet, uint32_t timeout) {

	/* Send envelope */
	char satid = (char) csp_rtable_find_mac(packet->id.dst);
	if (satid == (char) 255)
		satid = packet->id.dst;

	uint16_t length = packet->length;
	char * satidptr = ((char *) &packet->id) - 1;
	memcpy(satidptr, &satid, 1);
	csp_bin_sem_wait(&tx_wait, CSP_INFINITY); /* Using ZMQ in thread safe manner*/
	int result = zmq_send(publisher, satidptr, length + sizeof(packet->id) + sizeof(char), 0);
	csp_bin_sem_post(&tx_wait); /* Release tx semaphore */
	if (result < 0)
		csp_log_error("ZMQ send error: %u %s\r\n", result, strerror(result));

	csp_buffer_free(packet);

	return CSP_ERR_NONE;

}

CSP_DEFINE_TASK(csp_zmqhub_task) {

	while(1) {
		zmq_msg_t msg;
		assert(zmq_msg_init_size(&msg, 1024) == 0);

		/* Receive data */
		if (zmq_msg_recv(&msg, subscriber, 0) < 0) {
			zmq_msg_close(&msg);
			csp_log_error("ZMQ: %s", zmq_strerror(zmq_errno()));
			continue;
		}

		int datalen = zmq_msg_size(&msg);
		if (datalen < 5) {
			csp_log_warn("ZMQ: Too short datalen: %u", datalen);
			while(zmq_msg_recv(&msg, subscriber, ZMQ_NOBLOCK) > 0)
			zmq_msg_close(&msg);
			continue;
		}

		/* Create new csp packet */
		csp_packet_t * packet = csp_buffer_get(256);
		if (packet == NULL) {
			zmq_msg_close(&msg);
			continue;
		}

		/* Copy the data from zmq to csp */
		char * satidptr = ((char *) &packet->id) - 1;
		memcpy(satidptr, zmq_msg_data(&msg), datalen);
		packet->length = datalen - 4 - 1;

		/* Queue up packet to router */
		csp_qfifo_write(packet, &csp_if_zmqhub, NULL);

		zmq_msg_close(&msg);
	}

	return CSP_TASK_RETURN;

}

int csp_zmqhub_init(char _addr, char * host) {
	char url_pub[100];
	char url_sub[100];

	sprintf(url_pub, "tcp://%s:6000", host);
	sprintf(url_sub, "tcp://%s:7000", host);

	return csp_zmqhub_init_w_endpoints(_addr, url_pub, url_sub);
}

int csp_zmqhub_init_w_endpoints(char _addr, char * publisher_endpoint,
		char * subscriber_endpoint) {

	context = zmq_ctx_new();
	assert(context);

	char addr = _addr;

	csp_log_info("INIT ZMQ with addr %hhu to servers %s / %s\r\n", addr,
		publisher_endpoint, subscriber_endpoint);

	/* Publisher (TX) */
	publisher = zmq_socket(context, ZMQ_PUB);
	assert(publisher);
	assert(zmq_connect(publisher, publisher_endpoint) == 0);

	/* Subscriber (RX) */
	subscriber = zmq_socket(context, ZMQ_SUB);
	assert(subscriber);
	assert(zmq_connect(subscriber, subscriber_endpoint) == 0);

	if (addr == (char) 255) {
		assert(zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0) == 0);
	} else {
		assert(zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, &addr, 1) == 0);
	}
	/* ZMQ isn't thread safe, so we add a binary semaphore to wait on for tx */
	if (csp_bin_sem_create(&tx_wait) != CSP_SEMAPHORE_OK) {
		csp_log_error("Failed to initialize semaphore in csp_zmqhub_init_w_endpoints");
		return CSP_ERR_NOMEM;
	}
	/* Start RX thread */
	static csp_thread_handle_t handle_subscriber;
	int res = csp_thread_create(csp_zmqhub_task, "ZMQ", 10000, NULL, 0, &handle_subscriber);
	if (res != 0) {
            csp_log_error("%s: csp_thread_create() failed, res: %d, errno: %d", res, errno);
            return CSP_ERR_DRIVER;
	}

	/* Register interface */
	csp_iflist_add(&csp_if_zmqhub);

	return CSP_ERR_NONE;

}

/* Interface definition */
csp_iface_t csp_if_zmqhub = {
	.name = "ZMQHUB",
	.nexthop = csp_zmqhub_tx,
};
