#!/usr/bin/python

# libcsp must be build with at least these options to run this example client:
# ./waf distclean configure build --enable-bindings --enable-crc32 --enable-rdp --enable-if-zmq
#                                 --with-driver-usart=linux --enable-if-kiss --enable-xtea --enable-if-can
#                                 --enable-can-socketcan --enable-hmac --enable-examples
# Can be run from root of libcsp like this:
# LD_LIBRARY_PATH=build PYTHONPATH=bindings/python:build python examples/python_bindings_example_client.py
#

import os
import time
import libcsp as csp


if __name__ == "__main__":

    csp.init(28, "host", "model", "revision", 10, 300)
    #csp.can_socketcan_init("can0")
    csp.zmqhub_init(28, "localhost")
    csp.rtable_set(0, 0, "ZMQHUB")

    csp.route_start_task()
    
    # allow router task startup
    time.sleep(1)

    node = 27
    res = csp.ping(node)
    if res >= 0:
        print("Pinged %d in %d mS" % (node, res))
    else:
        print("Unable to ping node %d, error: %d" % (node, res))
