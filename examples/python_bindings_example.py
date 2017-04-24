#!/usr/bin/python

# libcsp must be build with at least these options to run this example:
# ./waf distclean configure build --enable-bindings --with-driver-usart=linux --enable-crc32 --enable-rdp --enable-if-zmq --enable-if-can --enable-can-socketcan=linux --enable-python3-bindings

# Can be run from root of libcsp like this:
# LD_LIBRARY_PATH=build PYTHONPATH=build python examples/python_bindings_example.py
#

import sys
import os
import time

if sys.version_info >= (3, 0):
    from libcsp_py3 import *
else:
    from libcsp_py2 import *

if __name__ == "__main__":

    # init csp
    
    print("csp_buffer_init: 10, 300")
    csp_buffer_init(10, 300)
    
    print("csp_init: 27")
    csp_init(27)
    
    print("csp_zmqhub_init: 27, localhost")
    csp_zmqhub_init(27, "localhost")

    print("csp_can_init: CSP_CAN_MASKED");  
    csp_can_init(CSP_CAN_MASKED)
    
    print ("csp_rtable_set: 7, 5")
    csp_rtable_set(7, 5, csp_zmqhub_if(), CSP_NODE_MAC)
    
    print ("csp_rtable_set: 30, 5")
    csp_rtable_set(30, 5, csp_can_if(), CSP_NODE_MAC)
    
    print ("csp_route_start_task: 1000, 0")
    csp_route_start_task(1000, 0)
    time.sleep(1) # allow router startup
    
    print ("csp_rtable_print")
    csp_rtable_print()

    print("pinging addr 7, rc=" + str(csp_ping(30, 5000, 10)))

    # start listening for packets...
    sock = csp_socket()
    csp_bind(sock, CSP_ANY)
    csp_listen(sock, 10)
    while True:
        conn = csp_accept(sock, 100)
        if not conn:
            continue

        while True:
            packet = csp_read(conn, 100)
            if not packet:
                break

            print("got packet, len=" + str(packet_length(packet)))

            csp_buffer_free(packet)
        csp_close(conn)

