/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2012 Gomspace ApS (http://www.gomspace.com)
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

#ifndef _CSP_SFP_H_
#define _CSP_SFP_H_

/**
   @file

   Simple Fragmentation Protocol.
*/

#include <csp/csp_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Send multiple packets using the simple fragmentation protocol
 * CSP will add total size and offset to all packets
 * This can be read by the client using the csp_sfp_recv, if the CSP_FFRAG flag is set
 * @param conn pointer to connection
 * @param data pointer to data to send
 * @param totalsize size of data to send
 * @param mtu maximum transfer unit
 * @param timeout timeout in ms to wait for csp_send()
 * @return 0 if OK, -1 if ERR
 */
int csp_sfp_send(csp_conn_t * conn, const void * data, int totalsize, int mtu, uint32_t timeout);

/**
 * Same as csp_sfp_send but with option to supply your own memcpy function.
 * This is usefull if you wish to send data stored in flash memory or another location
 * @param conn pointer to connection
 * @param data pointer to data to send
 * @param totalsize size of data to send
 * @param mtu maximum transfer unit
 * @param timeout timeout in ms to wait for csp_send()
 * @param memcpyfcn memcpy function.
 * @return 0 if OK, -1 if ERR
 */
int csp_sfp_send_own_memcpy(csp_conn_t * conn, const void * data, int totalsize, int mtu, uint32_t timeout, csp_memcpy_fnc_t memcpyfcn);

/**
 * This is the counterpart to the csp_sfp_send function
 * @param conn pointer to active conn, on which you expect to receive sfp packed data
 * @param dataout pointer to NULL pointer, whill be overwritten with malloc pointer
 * @param datasize actual size of received data
 * @param timeout timeout in ms to wait for csp_recv()
 * @return 0 if OK, -1 if ERR
 */
int csp_sfp_recv(csp_conn_t * conn, void ** dataout, int * datasize, uint32_t timeout);

/**
 * This is the counterpart to the csp_sfp_send function
 * @param conn pointer to active conn, on which you expect to receive sfp packed data
 * @param dataout pointer to NULL pointer, whill be overwritten with malloc pointer
 * @param datasize actual size of received data
 * @param timeout timeout in ms to wait for csp_recv()
 * @param first_packet This is a pointer to the first SFP packet (previously received with csp_read)
 * @return 0 if OK, -1 if ERR
 */
int csp_sfp_recv_fp(csp_conn_t * conn, void ** dataout, int * datasize, uint32_t timeout, csp_packet_t * first_packet);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif // _CSP_SFP_H_
