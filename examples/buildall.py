#!/usr/bin/env python
# encoding: utf-8

import subprocess


options = [
    '--enable-rdp',
    '--enable-qos',
    '--enable-promisc',
    '--enable-crc32',
    '--enable-hmac',
    '--enable-xtea',
    '--enable-dedup',
]

linux_options = [
    '--enable-socketcan',
    '--enable-zmq',
    '--enable-bindings',
    '--enable-python3-bindings',
    '--with-driver-usart=linux',
    '--with-os=posix',
]

# Build on linux
subprocess.check_call(['./waf', 'distclean', 'configure', 'build'] + options + linux_options +
                      ['--enable-init-shutdown', '--with-rtable=cidr', '--disable-stlib', '--disable-output'])
subprocess.check_call(['./waf', 'distclean', 'configure', 'build'] + options + linux_options +
                      ['--enable-examples'])
