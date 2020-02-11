#!/usr/bin/python

# libcsp must be build with at least these options to run this example server:
# ./waf distclean configure build --enable-bindings --enable-crc32 --enable-rdp --enable-if-zmq
#                                 --enable-can-socketcan --enable-examples
# Can be run from root of libcsp like this:
# LD_LIBRARY_PATH=build PYTHONPATH=bindings/python:build python examples/python_bindings_example_server.py
#

import os
import time
import sys
import libcsp as csp
import threading

def thread_function(name):
    i = 0;
    while True:
        print("Thread %s: running, %d" % (name, i))
        i = i + 1
        time.sleep(1)

if __name__ == "__main__":

    # init csp
    csp.init(27, "test_service", "bindings", "1.2.3", 10, 300)
    csp.zmqhub_init(27, "localhost")
    csp.rtable_set(0, 0, "ZMQHUB")
    csp.route_start_task()

    print("Hostname: %s" % csp.get_hostname())
    print("Model:    %s" % csp.get_model())
    print("Revision: %s" % csp.get_revision())

    print("Print connections:")
    csp.print_connections()
    print("Print routes:")
    csp.print_routes()
    buffer_stats = csp.get_buffer_stats()
    print("Buffer stats: remaining: %d, total-size: %d, data-size: %d" % (buffer_stats[0], buffer_stats[1], buffer_stats[2]))

    # threading.Thread(target=thread_function, args=(1,)).start()
    
    # start listening for packets...
    sock = csp.socket()
    csp.bind(sock, csp.CSP_ANY)
    csp.listen(sock)
    while True:
        buffer_stats = csp.get_buffer_stats()
        print("Buffer stats: remaining: %d, total-size: %d, data-size: %d" % (buffer_stats[0], buffer_stats[1], buffer_stats[2]))
        print("Print connections:")
        csp.print_connections()

        # wait for incoming connection
        conn = csp.accept(sock)
        if not conn:
            print("timeout on csp.accept()")
            continue

        print ("connection: source=%i:%i, dest=%i:%i" % (csp.conn_src(conn),
                                                         csp.conn_sport(conn),
                                                         csp.conn_dst(conn),
                                                         csp.conn_dport(conn)))

        while True:
            # Read all packets on the connection
            packet = csp.read(conn)
            if not packet:
                break

            if csp.conn_dport(conn) == 10:
                data = bytearray(csp.packet_get_data(packet))
                length = csp.packet_get_length(packet)
                print ("got packet, len=" + str(length) + ", data=" + ''.join('{:02x}'.format(x) for x in data))

                data[0] = data[0] + 1
                reply_packet = csp.buffer_get(1)
                if reply_packet:
                    csp.packet_set_data(reply_packet, data)
                    csp.sendto_reply(packet, reply_packet, csp.CSP_O_NONE)

            else:
                csp.service_handler(conn, packet)
        # csp.close(conn)
