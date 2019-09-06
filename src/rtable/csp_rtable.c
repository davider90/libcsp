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

#include <alloca.h>
#include <stdio.h>
#include <csp/csp.h>
#include <csp/csp_rtable.h>
#include <csp/csp_iflist.h>
#include <csp/interfaces/csp_if_lo.h>
#include "../csp_init.h"

static int csp_rtable_parse(const char * rtable, int dry_run) {

	int valid_entries = 0;

	/* Copy string before running strtok */
	char * str = alloca(strlen(rtable) + 1);
	memcpy(str, rtable, strlen(rtable) + 1);

	/* Get first token */
	str = strtok(str, ",");

	while ((str) && (strlen(str) > 1)) {
		unsigned int address = 0, netmask = 0, mac = CSP_NODE_MAC;
		char name[10] = {};
		if (sscanf(str, "%u/%u %s %u", &address, &netmask, name, &mac) == 4) {
                } else if (sscanf(str, "%u/%u %s", &address, &netmask, name) == 3) {
                    mac = CSP_NODE_MAC;
                } else if (sscanf(str, "%u %s %u", &address, name, &mac) == 3) {
                    netmask = CSP_ID_HOST_SIZE;
                } else if (sscanf(str, "%u %s", &address, name) == 3) {
                    netmask = CSP_ID_HOST_SIZE;
                    mac = CSP_NODE_MAC;
                } else {
                    csp_log_error("%s: parse error [%s]", __FUNCTION__, str);
                    return -1;
                }

		//printf("Parsed %u/%u %u %s\r\n", address, netmask, mac, name);
		csp_iface_t * ifc = csp_iflist_get_by_name(name);
                if (ifc == NULL) {
                    csp_log_error("%s: unknown interface [%s] in [%s]", __FUNCTION__, name, str);
                    return -1;
                }
                if (dry_run == 0) {
                    int res = csp_rtable_set(address, netmask, ifc, mac);
                    if (res != CSP_ERR_NONE) {
                        csp_log_error("%s: failed to add [%s], error: %d", __FUNCTION__, str, res);
                        return -1;
                    }
		}
		valid_entries++;
		str = strtok(NULL, ",");
	}

	return valid_entries;
}

int csp_rtable_load(const char * rtable) {
	return csp_rtable_parse(rtable, 0);
}

int csp_rtable_check(const char * rtable) {
	return csp_rtable_parse(rtable, 1);
}

typedef struct {
    char * buffer;
    int len;
    int maxlen;
} csp_rtable_save_ctx_t;

static bool csp_rtable_save_route(void * vctx, uint8_t address, uint8_t mask, const csp_rtable_route_t * route)
{
    csp_rtable_save_ctx_t * ctx = vctx;

    // Do not save loop back interface
    if (strcasecmp(route->interface->name, CSP_IF_LOOPBACK_NAME) == 0) {
        return true;
    }

    const char * sep = (ctx->len == 0) ? "" : ",";

    char mask_str[10];
    if (mask != CSP_ID_HOST_SIZE) {
        snprintf(mask_str, sizeof(mask_str), "/%u", mask);
    } else {
        mask_str[0] = 0;
    }
    char mac_str[10];
    if (route->mac != CSP_NODE_MAC) {
        snprintf(mac_str, sizeof(mac_str), " %u", route->mac);
    } else {
        mac_str[0] = 0;
    }
    ctx->len += snprintf(ctx->buffer + ctx->len, ctx->maxlen - ctx->len,
                         "%s%u%s %s%s", sep, address, mask_str, route->interface->name, mac_str);
    return true;
}

int csp_rtable_save(char * buffer, int maxlen)
{
    csp_rtable_save_ctx_t ctx = {.len = 0, .buffer = buffer, .maxlen = maxlen};
    csp_rtable_iterate(csp_rtable_save_route, &ctx);
    // TODO error handling
    return ctx.len;
}

void csp_rtable_clear(void) {
	csp_rtable_free();

	/* Set loopback up again */
	csp_rtable_set(csp_conf.address, CSP_ID_HOST_SIZE, &csp_if_lo, CSP_NODE_MAC);
}

csp_iface_t * csp_rtable_find_iface(uint8_t address)
{
    const csp_rtable_route_t * route = csp_rtable_find_route(address);
    if (route) {
        return route->interface;
    }
    return NULL;
}

uint8_t csp_rtable_find_mac(uint8_t address)
{
    const csp_rtable_route_t * route = csp_rtable_find_route(address);
    if (route) {
	return route->mac;
    }
    return CSP_NODE_MAC;
}

#ifdef CSP_DEBUG

static bool csp_rtable_print_route(void * ctx, uint8_t address, uint8_t mask, const csp_rtable_route_t * route)
{
    if (route->mac == CSP_NODE_MAC) {
        printf("%u/%u %s\r\n", address, mask, route->interface->name);
    } else {
        printf("%u/%u %s %u\r\n", address, mask, route->interface->name, route->mac);
    }
    return true;
}

void csp_rtable_print(void)
{
    csp_rtable_iterate(csp_rtable_print_route, NULL);
}

#endif
