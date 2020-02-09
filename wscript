#!/usr/bin/env python
# encoding: utf-8

# Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
# Copyright (C) 2012 GomSpace ApS (http://www.gomspace.com)
# Copyright (C) 2012 AAUSAT3 Project (http://aausat3.space.aau.dk)
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import os

APPNAME = 'libcsp'
VERSION = '1.6'


def options(ctx):
    # Load GCC options
    ctx.load('gcc')

    ctx.add_option('--toolchain', default=None, help='Set toolchain prefix')

    # Set libcsp options
    gr = ctx.add_option_group('libcsp options')
    gr.add_option('--includes', default='', help='Add additional include paths. Separate with comma')
    gr.add_option('--install-csp', action='store_true', help='Installs CSP headers and lib')

    gr.add_option('--disable-output', action='store_true', help='Disable CSP output')
    gr.add_option('--disable-stlib', action='store_true', help='Build objects only')
    gr.add_option('--enable-rdp', action='store_true', help='Enable RDP support')
    gr.add_option('--enable-qos', action='store_true', help='Enable Quality of Service support')
    gr.add_option('--enable-promisc', action='store_true', help='Enable promiscuous mode support')
    gr.add_option('--enable-crc32', action='store_true', help='Enable CRC32 support')
    gr.add_option('--enable-hmac', action='store_true', help='Enable HMAC-SHA1 support')
    gr.add_option('--enable-xtea', action='store_true', help='Enable XTEA support')
    gr.add_option('--enable-bindings', action='store_true', help='Enable Python bindings')
    gr.add_option('--enable-python3-bindings', action='store_true', help='Enable Python3 bindings')
    gr.add_option('--enable-examples', action='store_true', help='Enable examples')
    gr.add_option('--enable-dedup', action='store_true', help='Enable packet deduplicator')
    gr.add_option('--enable-external-debug', action='store_true', help='Enable external debug API')

    # Interfaces
    gr.add_option('--enable-if-i2c', action='store_true', help='Enable I2C interface')
    gr.add_option('--enable-if-kiss', action='store_true', help='Enable KISS/RS.232 interface')
    gr.add_option('--enable-if-can', action='store_true', help='Enable CAN interface')
    gr.add_option('--enable-if-zmqhub', action='store_true', help='Enable ZMQHUB interface')

    # Drivers
    gr.add_option('--enable-can-socketcan', action='store_true', help='Enable Linux socketcan driver')
    gr.add_option('--with-driver-usart', default=None, metavar='DRIVER',
                  help='Build USART driver. [windows, linux, None]')

    # OS
    gr.add_option('--with-os', metavar='OS', default='posix',
                  help='Set operating system. Must be either \'posix\', \'macosx\', \'windows\' or \'freertos\'')
    gr.add_option('--enable-init-shutdown', action='store_true', help='Use init system commands for shutdown/reboot')

    # Options
    gr.add_option('--with-loglevel', metavar='LEVEL', default='debug',
                  help='Set minimum compile time log level. Must be one of \'error\', \'warn\', \'info\' or \'debug\'')
    gr.add_option('--with-rtable', metavar='TABLE', default='static',
                  help='Set routing table type: \'static\' or \'cidr\'')


def configure(ctx):
    # Validate options
    valid_os = ['posix', 'windows', 'freertos', 'macosx']
    if ctx.options.with_os not in valid_os:
        ctx.fatal('--with-os must be either: ' + str(valid_os))

    valid_loglevel = ['error', 'warn', 'info', 'debug']
    if ctx.options.with_loglevel not in valid_loglevel:
        ctx.fatal('--with-loglevel must be either: ' + str(valid_loglevel))

    # Setup and validate toolchain
    if (len(ctx.stack_path) <= 1) and ctx.options.toolchain:
        ctx.env.CC = ctx.options.toolchain + 'gcc'
        ctx.env.AR = ctx.options.toolchain + 'ar'

    ctx.load('gcc')

    # Set git revision define
    git_rev = os.popen('git describe --always 2> /dev/null || echo unknown').read().strip()

    # Setup DEFINES
    ctx.define('GIT_REV', git_rev)

    # Set build output format
    ctx.env.FEATURES = ['c']
    if not ctx.options.disable_stlib:
        ctx.env.FEATURES += ['cstlib']

    # Setup CFLAGS
    if (len(ctx.stack_path) <= 1) and (len(ctx.env.CFLAGS) == 0):
        ctx.env.prepend_value('CFLAGS', ["-std=gnu99", "-g", "-Os", "-Wall", "-Wextra", "-Wshadow", "-Wcast-align",
                                         "-Wwrite-strings", "-Wno-unused-parameter"])

    # Setup extra includes
    ctx.env.append_unique('INCLUDES_CSP', ['include'] + ctx.options.includes.split(','))

    # Store OS as env variable
    ctx.env.append_unique('OS', ctx.options.with_os)

    # Libs
    if 'posix' in ctx.env.OS:
        ctx.env.append_unique('LIBS', ['rt', 'pthread', 'util'])
    elif 'macosx' in ctx.env.OS:
        ctx.env.append_unique('LIBS', ['pthread'])

    # Check for recursion
    if ctx.path == ctx.srcnode:
        ctx.options.install_csp = True

    # Windows build flags
    if ctx.options.with_os == 'windows':
        ctx.env.append_unique('CFLAGS', ['-D_WIN32_WINNT=0x0600'])

    ctx.define_cond('CSP_FREERTOS', ctx.options.with_os == 'freertos')
    ctx.define_cond('CSP_POSIX', ctx.options.with_os == 'posix')
    ctx.define_cond('CSP_WINDOWS', ctx.options.with_os == 'windows')
    ctx.define_cond('CSP_MACOSX', ctx.options.with_os == 'macosx')

    # Add default files
    ctx.env.append_unique('FILES_CSP', ['src/*.c',
                                        'src/interfaces/csp_if_lo.c',
                                        'src/transport/csp_udp.c',
                                        'src/arch/{0}/**/*.c'.format(ctx.options.with_os),
                                        'src/rtable/csp_rtable.c',
                                        'src/rtable/csp_rtable_{0}.c'.format(ctx.options.with_rtable)])

    # Add CAN driver
    if ctx.options.enable_can_socketcan:
        ctx.env.append_unique('FILES_CSP', 'src/drivers/can/can_socketcan.c')

    # Add USART driver
    if ctx.options.with_driver_usart:
        ctx.env.append_unique('FILES_CSP', 'src/drivers/usart/usart_{0}.c'.format(ctx.options.with_driver_usart))

    # Interfaces
    if ctx.options.enable_if_can:
        ctx.env.append_unique('FILES_CSP', ['src/interfaces/csp_if_can.c', 'src/interfaces/csp_if_can_pbuf.c'])
    if ctx.options.enable_if_i2c:
        ctx.env.append_unique('FILES_CSP', 'src/interfaces/csp_if_i2c.c')
    if ctx.options.enable_if_kiss:
        ctx.env.append_unique('FILES_CSP', 'src/interfaces/csp_if_kiss.c')
    if ctx.options.enable_if_zmqhub:
        ctx.env.append_unique('FILES_CSP', 'src/interfaces/csp_if_zmqhub.c')
        ctx.check_cfg(package='libzmq', args='--cflags --libs')
        ctx.env.append_unique('LIBS', ctx.env.LIB_LIBZMQ)

    # Store configuration options
    ctx.env.ENABLE_BINDINGS = ctx.options.enable_bindings
    ctx.env.ENABLE_EXAMPLES = ctx.options.enable_examples

    # Check for python development
    if ctx.options.enable_bindings:
        ctx.env.LIBCSP_PYTHON2 = ctx.check_cfg(package='python2', args='--cflags --libs', atleast_version='2.7',
                                               mandatory=False)
        if ctx.options.enable_python3_bindings:
            ctx.env.LIBCSP_PYTHON3 = ctx.check_cfg(package='python3', args='--cflags --libs', atleast_version='3.5',
                                                   mandatory=False)

    # Check options
    if ctx.options.disable_output:
        ctx.env.append_unique('EXCL_CSP', 'src/csp_debug.c')

    if ctx.options.enable_rdp:
        ctx.env.append_unique('FILES_CSP', 'src/transport/csp_rdp.c')

    if not ctx.options.enable_crc32:
        ctx.env.append_unique('EXCL_CSP', 'src/csp_crc32.c')

    if not ctx.options.enable_dedup:
        ctx.env.append_unique('EXCL_CSP', 'src/csp_dedup.c')

    if ctx.options.enable_hmac:
        ctx.env.append_unique('FILES_CSP', ['src/crypto/csp_hmac.c', 'src/crypto/csp_sha1.c'])

    if ctx.options.enable_xtea:
        ctx.env.append_unique('FILES_CSP', ['src/crypto/csp_xtea.c', 'src/crypto/csp_sha1.c'])

    if ctx.options.enable_external_debug:
        ctx.env.append_unique('EXCL_CSP', 'src/csp_debug.c')
        ctx.env.append_unique('FILES_CSP', 'src/external/*.c')

    ctx.define_cond('CSP_DEBUG', not ctx.options.disable_output)
    ctx.define_cond('CSP_USE_RDP', ctx.options.enable_rdp)
    ctx.define_cond('CSP_USE_CRC32', ctx.options.enable_crc32)
    ctx.define_cond('CSP_USE_HMAC', ctx.options.enable_hmac)
    ctx.define_cond('CSP_USE_XTEA', ctx.options.enable_xtea)
    ctx.define_cond('CSP_USE_PROMISC', ctx.options.enable_promisc)
    ctx.define_cond('CSP_USE_QOS', ctx.options.enable_qos)
    ctx.define_cond('CSP_USE_DEDUP', ctx.options.enable_dedup)
    ctx.define_cond('CSP_USE_INIT_SHUTDOWN', ctx.options.enable_init_shutdown)
    ctx.define_cond('CSP_USE_CAN', ctx.options.enable_if_can)
    ctx.define_cond('CSP_USE_I2C', ctx.options.enable_if_i2c)
    ctx.define_cond('CSP_USE_KISS', ctx.options.enable_if_kiss)
    ctx.define_cond('CSP_USE_ZMQHUB', ctx.options.enable_if_zmqhub)
    ctx.define_cond('CSP_USE_EXTERNAL_DEBUG', ctx.options.enable_external_debug)

    # Set logging level
    ctx.define_cond('CSP_LOG_LEVEL_DEBUG', ctx.options.with_loglevel in ('debug'))
    ctx.define_cond('CSP_LOG_LEVEL_INFO', ctx.options.with_loglevel in ('debug', 'info'))
    ctx.define_cond('CSP_LOG_LEVEL_WARN', ctx.options.with_loglevel in ('debug', 'info', 'warn'))
    ctx.define_cond('CSP_LOG_LEVEL_ERROR', ctx.options.with_loglevel in ('debug', 'info', 'warn', 'error'))

    # Check compiler endianness
    endianness = ctx.check_endianness()
    ctx.define_cond('CSP_LITTLE_ENDIAN', endianness == 'little')
    ctx.define_cond('CSP_BIG_ENDIAN', endianness == 'big')

    # Check for stdbool.h
    ctx.check_cc(header_name='stdbool.h', mandatory=False, define_name='CSP_HAVE_STDBOOL_H', type='cstlib')

    # Check for libsocketcan.h
    if ctx.options.enable_if_can and ctx.options.enable_can_socketcan:
        have_socketcan = ctx.check_cc(lib='socketcan', mandatory=False, define_name='CSP_HAVE_LIBSOCKETCAN')
        if have_socketcan:
            ctx.env.append_unique('LIBS', ['socketcan'])

    ctx.define('LIBCSP_VERSION', VERSION)

    ctx.write_config_header('include/csp/csp_autoconfig.h')


def build(ctx):

    # Set install path for header files
    install_path = False
    if ctx.options.install_csp:
        install_path = '${PREFIX}/lib'
        ctx.install_files('${PREFIX}/include/csp', ctx.path.ant_glob('include/csp/*.h'))
        ctx.install_files('${PREFIX}/include/csp/interfaces', 'include/csp/interfaces/csp_if_lo.h')

        if 'src/interfaces/csp_if_can.c' in ctx.env.FILES_CSP:
            ctx.install_files('${PREFIX}/include/csp/interfaces', 'include/csp/interfaces/csp_if_can.h')
        if 'src/interfaces/csp_if_i2c.c' in ctx.env.FILES_CSP:
            ctx.install_files('${PREFIX}/include/csp/interfaces', 'include/csp/interfaces/csp_if_i2c.h')
        if 'src/interfaces/csp_if_kiss.c' in ctx.env.FILES_CSP:
            ctx.install_files('${PREFIX}/include/csp/interfaces', 'include/csp/interfaces/csp_if_kiss.h')
        if 'src/interfaces/csp_if_zmqhub.c' in ctx.env.FILES_CSP:
            ctx.install_files('${PREFIX}/include/csp/interfaces', 'include/csp/interfaces/csp_if_zmqhub.h')
        if 'src/drivers/usart/usart_{0}.c'.format(ctx.options.with_driver_usart) in ctx.env.FILES_CSP:
            ctx.install_as('${PREFIX}/include/csp/drivers/usart.h', 'include/csp/drivers/usart.h')
        if 'src/drivers/can/can_socketcan.c' in ctx.env.FILES_CSP:
            ctx.install_as('${PREFIX}/include/csp/drivers/can_socketcan.h', 'include/csp/drivers/can_socketcan.h')

        ctx.install_files('${PREFIX}/include/csp', 'include/csp/csp_autoconfig.h', cwd=ctx.bldnode)

    ctx(export_includes=ctx.env.INCLUDES_CSP, name='csp_h')

    ctx(features=ctx.env.FEATURES,
        source=ctx.path.ant_glob(ctx.env.FILES_CSP, excl=ctx.env.EXCL_CSP),
        target='csp',
        use=['csp_h', 'freertos_h', 'util'],
        install_path=install_path)

    # Build shared library for Python bindings
    if ctx.env.ENABLE_BINDINGS:
        ctx.shlib(source=ctx.path.ant_glob(ctx.env.FILES_CSP, excl=ctx.env.EXCL_CSP),
                  name='csp_shlib',
                  target='csp',
                  use=['csp_h', 'util_shlib'],
                  lib=ctx.env.LIBS)

        # python3 bindings
        if ctx.env.LIBCSP_PYTHON3:
            ctx.shlib(source=['src/bindings/python/pycsp.c'],
                      target='csp_py3',
                      includes=ctx.env.INCLUDES_PYTHON3,
                      use=['csp_shlib'],
                      lib=ctx.env.LIBS)

        # python2 bindings
        if ctx.env.LIBCSP_PYTHON2:
            ctx.shlib(source=['src/bindings/python/pycsp.c'],
                      target='csp_py2',
                      includes=ctx.env.INCLUDES_PYTHON2,
                      use=['csp_shlib'],
                      lib=ctx.env.LIBS)

    if ctx.env.ENABLE_EXAMPLES:
        ctx.program(source='examples/simple.c',
                    target='simple',
                    lib=ctx.env.LIBS,
                    use='csp')

        if ctx.options.enable_if_kiss:
            ctx.program(source='examples/kiss.c',
                        target='kiss',
                        lib=ctx.env.LIBS,
                        use='csp')

        if ctx.options.enable_if_zmqhub:
            ctx.program(source='examples/zmqproxy.c',
                        target='zmqproxy',
                        lib=ctx.env.LIBS,
                        use='csp')

        if 'posix' in ctx.env.OS:
            ctx.program(source='examples/csp_if_fifo.c',
                        target='fifo',
                        lib=ctx.env.LIBS,
                        use=['csp'])

        if 'windows' in ctx.env.OS:
            ctx.program(source=ctx.path.ant_glob('examples/csp_if_fifo_windows.c'),
                        target='csp_if_fifo',
                        use='csp')


def dist(ctx):
    ctx.excl = 'build/* **/.* **/*.pyc **/*.o **/*~ *.tar.gz'
