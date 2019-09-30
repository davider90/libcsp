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

#include <csp/drivers/can_socketcan.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can/raw.h>
#ifdef CSP_HAVE_LIBSOCKETCAN
#include <libsocketcan.h>
#endif
#include <csp/csp.h>

typedef struct {
    char name[CSP_IFLIST_NAME_MAX + 1];
    csp_iface_t iface;
    csp_can_interface_data_t ifdata;
    pthread_t rx_thread;
    int socket;
} can_context_t;

static void socketcan_free(can_context_t * ctx)
{
    if (ctx) {
        if (ctx->socket >= 0) {
            close(ctx->socket);
        }
        free(ctx);
    }
}

static void * socketcan_rx_thread(void * arg)
{
	can_context_t * ctx = arg;

	while (1) {
		/* Read CAN frame */
		struct can_frame frame;
		int nbytes = read(ctx->socket, &frame, sizeof(frame));
		if (nbytes < 0) {
			csp_log_error("%s: read() failed, error: %s", __FUNCTION__, strerror(errno));
			continue;
		}

		if (nbytes != sizeof(frame)) {
			csp_log_warn("%s: Read incomplete CAN frame, size: %u, expected: %lu bytes", __FUNCTION__, nbytes, sizeof(frame));
			continue;
		}

		/* Frame type */
		if (frame.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG) || !(frame.can_id & CAN_EFF_FLAG)) {
			/* Drop error and remote frames */
			csp_log_warn("%s: discarding ERR/RTR/SFF frame", __FUNCTION__);
			continue;
		}

		/* Strip flags */
		frame.can_id &= CAN_EFF_MASK;

		/* Call RX callbacsp_can_rx_frameck */
		csp_can_rx(&ctx->iface, frame.can_id, frame.data, frame.can_dlc, NULL);
	}

	/* We should never reach this point */
	pthread_exit(NULL);
}


static int csp_can_tx_frame(void * driver_data, uint32_t id, const uint8_t * data, uint8_t dlc, uint32_t timeout)
{
	if (dlc > 8) {
		return CSP_ERR_INVAL;
	}

	/* Copy identifier */
	struct can_frame frame = {.can_id = id | CAN_EFF_FLAG,
                                  .can_dlc = dlc};
        memcpy(frame.data, data, dlc);

	/* Send frame */
	int tries = 0;
        can_context_t * ctx = driver_data;

	while (write(ctx->socket, &frame, sizeof(frame)) != sizeof(frame)) {
		if (++tries < 1000 && errno == ENOBUFS) {
			/* Wait 10 ms and try again*/
			// cppcheck-suppress usleepCalled 
			usleep(10000);
		} else {
			csp_log_error("%s: write: %s", __FUNCTION__, strerror(errno));
			return CSP_ERR_TX;
		}
	}

	return CSP_ERR_NONE;
}

csp_iface_t * csp_can_socketcan_init(const char * device, const char * ifname, int bitrate, bool promisc)
{
	csp_log_info("%s: device: [%s], interface: [%s], bitrate: %d, promisc: %d",
			__FUNCTION__, device, ifname, bitrate, promisc);

#ifdef CSP_HAVE_LIBSOCKETCAN
	/* Set interface up - this may require increased OS privileges */
	if (bitrate > 0) {
		can_do_stop(device);
		can_set_bitrate(device, bitrate);
		can_set_restart_ms(device, 100);
		can_do_start(device);
	}
#endif

	can_context_t * ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->socket = -1;

	strncpy(ctx->name, ifname, sizeof(ctx->name) - 1);
	ctx->iface.name = ctx->name;
	ctx->iface.interface_data = &ctx->ifdata;
	ctx->iface.driver_data = ctx;
	ctx->ifdata.tx_func = csp_can_tx_frame;

	/* Create socket */
	if ((ctx->socket = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		csp_log_error("%s: socket() failed, error: %s", __FUNCTION__, strerror(errno));
		socketcan_free(ctx);
		return NULL;
	}

	/* Locate interface */
	struct ifreq ifr;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	if (ioctl(ctx->socket, SIOCGIFINDEX, &ifr) < 0) {
		csp_log_error("%s: ioctl() failed, error: %s", __FUNCTION__, strerror(errno));
		socketcan_free(ctx);
		return NULL;
	}
	struct sockaddr_can addr;
	memset(&addr, 0, sizeof(addr));
	/* Bind the socket to CAN interface */
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;
	if (bind(ctx->socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		csp_log_error("%s: bind() failed, error: %s", __FUNCTION__, strerror(errno));
		socketcan_free(ctx);
		return NULL;
	}

	/* Set filter mode */
	if (promisc == false) {

            struct can_filter filter = {.can_id = CFP_MAKE_DST(csp_get_address()),
                                        .can_mask = CFP_MAKE_DST((1 << CFP_HOST_SIZE) - 1)};

		if (setsockopt(ctx->socket, SOL_CAN_RAW, CAN_RAW_FILTER, &filter, sizeof(filter)) < 0) {
			csp_log_error("%s: setsockopt() failed, error: %s", __FUNCTION__, strerror(errno));
			socketcan_free(ctx);
			return NULL;
		}
	}

	/* Add interface to CSP */
        int res = csp_can_add_interface(&ctx->iface);
	if (res != CSP_ERR_NONE) {
		csp_log_error("%s: csp_can_add_interface() failed, error: %d", __FUNCTION__, res);
		socketcan_free(ctx);
		return NULL;
        }

	/* Create receive thread */
	if (pthread_create(&ctx->rx_thread, NULL, socketcan_rx_thread, ctx) != 0) {
		csp_log_error("%s: pthread_create() failed, error: %s", __FUNCTION__, strerror(errno));
		//socketcan_free(ctx); // we already added it to CSP (no way to remove it)
		return NULL;
	}

	return &ctx->iface;
}

int csp_can_socketcan_stop(csp_iface_t *iface)
{
        can_context_t * ctx = iface->driver_data;

	int error = pthread_cancel(ctx->rx_thread);
	if (error != 0) {
		csp_log_error("%s: pthread_cancel() failed, error: %s", __FUNCTION__, strerror(errno));
		return CSP_ERR_DRIVER;
	}
	error = pthread_join(ctx->rx_thread, NULL);
	if (error != 0) {
		csp_log_error("%s: pthread_join() failed, error: %s", __FUNCTION__, strerror(errno));
		return CSP_ERR_DRIVER;
	}
        socketcan_free(ctx);
	return CSP_ERR_NONE;
}
