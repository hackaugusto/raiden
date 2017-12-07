#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import binascii
import ctypes
import ctypes.util
import errno
import fcntl
import os
import random
import select
import socket
import string
import struct
import sys
from collections import namedtuple

STUN_SERVERS = (
    'stun.ekiga.net',
    'stun.ideasip.com',
    'stun.voiparound.com',
    'stun.voipbuster.com',
    'stun.voipstunt.com',
    'stun.voxgratia.org',
)
STUN_HEADER_LENGTH = 20
STUN_ATTRIBUTE_HEADER_LENGTH = 4
STUN_TRANSACTION_ID_MAX = 2 ** 96
STUN_TRANSACTION_ID_LEN = 12
STUN_MAXIMUM_LENGTH = 2 ** 16
STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'
STUN_FORMAT_HEADER = '>2sh4s12s'
STUN_FORMAT_ATTRIBUTE = '>2sh'
STUN_FORMAT_MAPPED_ADDRESS = '>cbh'

# https://tools.ietf.org/html/rfc5389#section-18.1
# STUN_METHOD_BINDING = b'\x00\x01'
STUN_BINDING_REQUEST = b'\x00\x01'
STUN_BINDING_RESPONSE = b'\x01\x01'
STUN_BINDING_ERROR = b'\x01\x11'

# https://tools.ietf.org/html/rfc5389#section-18.2
STUN_ATTRIBUTE_MAPPED_ADDRESS = b'\x00\x01'
STUN_ATTRIBUTE_USERNAME = b'\x00\x06'
STUN_ATTRIBUTE_MESSAGE_INTEGRITY = b'\x00\x08'
STUN_ATTRIBUTE_ERROR_CODE = b'\x00\x09'
STUN_ATTRIBUTE_REALM = b'\x00\x14'
STUN_ATTRIBUTE_NONCE = b'\x00\x15'
STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS = b'\x00\x20'

# https://tools.ietf.org/html/rfc5389#section-15.1
STUN_IPv4_FAMILY = 1
STUN_IPv6_FAMILY = 2
StunAttribute = namedtuple('StunAttribute', ('attribute_type', 'attribute_data'))
StunMappedAddress = namedtuple('StunMappedAddress', ('packed_address', 'address', 'port'))
StunResponseHeader = namedtuple(
    'StunResponseHeader',
    ('message_type', 'length', 'magic_cookie', 'transaction_id'),
)
StunResponseIndication = namedtuple('StunResponseIndication', ('attributes', ))
StunResponseSuccess = namedtuple('StunResponseSuccess', ('attributes', ))
StunResponseError = namedtuple('StunResponseError', ('attributes', ))

Init = object()
InputOneLine = namedtuple('InputOneLine', ('prompt'))
Exit = namedtuple('Exit', ('result', 'message'))
UDPReceive = namedtuple('UDPReceive', ('identifier', 'remote_endpoint', 'data'))
UDPSend = namedtuple('UDPSend', ('identifier', 'remote_endpoint', 'data'))
UDPNewSocket = namedtuple('UDPNewSocket', ('identifier', 'local_endpoint', 'endpoints_to_datum'))
TimerNew = namedtuple('TimerNew', ('identifier', 'interval_ms'))
TimerCancel = namedtuple('TimerNew', ('identifier', ))
StdinReceive = namedtuple('StdinReceive', ('data', ))
React = namedtuple(
    'ReactState',
    (
        'pollster',
        'databuffer',
        'fd_to_applicationid',
        'fd_to_socket',
        'applicationid_to_timer',
        'application',
    ),
)

ASK_REMOTEENDPOINT = InputOneLine('Please inform the target node *public* endpoint (ip:port):')

cint = ctypes.c_int
clong = ctypes.c_long


def clib(function, arguments_types, return_type):
    lib = ctypes.CDLL(ctypes.util.find_library('c'))

    func = getattr(lib, function)
    func.argtypes = arguments_types
    func.restype = return_type

    return func


class timespec(ctypes.Structure):
    # <bits/types.h>
    # typedef long int __time_t;
    # typedef long int __syscall_slong_t;
    #
    # <time.h>
    # typedef __time_t time_t;
    # struct timespec
    # {
    #     __time_t tv_sec;
    #     __syscall_slong_t tv_nsec;
    # };
    _fields_ = [
        ('tv_sec', clong),
        ('tv_nsec', clong),
    ]


class itimerspec(ctypes.Structure):
    # struct itimerspec
    # {
    #     struct timespec it_interval;
    #     struct timespec it_value;
    # };
    _fields_ = [
        ('it_interval', timespec),
        ('it_value', timespec),
    ]


# int timerfd_create(int, int);
timerfd_create = clib('timerfd_create', [cint, cint], cint)
# int timerfd_settime(int, int, const struct itimerspec, struct itimerspec);
settime = clib(
    'timerfd_settime',
    [cint, cint, ctypes.POINTER(itimerspec), ctypes.POINTER(itimerspec)],
    cint,
)
# int timerfd_gettime(int, struct itimerspec*);
gettime = clib('timerfd_gettime', [cint, cint, ctypes.POINTER(itimerspec)], cint)

# <bis/time.h>
CLOCK_REALTIME = 0      # Identifier for system-wide realtime clock.
CLOCK_MONOTONIC = 1     # Monotonic system-wide clock.

# <bits/timerfd.h>
TFD_CLOEXEC = 524288    # int('02000000', 8)
TFD_NONBLOCK = 2048     # int('00004000', 8)

NULL_SPEC = ctypes.POINTER(itimerspec)()


class Timer(object):
    def __init__(self, interval_ms, clock_type=CLOCK_MONOTONIC, flags=TFD_CLOEXEC | TFD_NONBLOCK):
        self._fileno = timerfd_create(cint(clock_type), cint(flags))
        fd_nonblocking(self._fileno)

        miliseconds = interval_ms % 1000
        seconds = interval_ms / 1000
        nanoseconds = miliseconds * 1000000

        repeat = timespec(seconds, nanoseconds)
        first = timespec(seconds, nanoseconds)

        spec = itimerspec(repeat, first)

        settime(self._fileno, 0, spec, NULL_SPEC)

    def fileno(self):
        return self._fileno

    def read(self):
        pass


class Application(object):
    def __init__(self, function, state, config):
        self.function = function
        self.state = state
        self.config = config


def new_udp_socket(local_endpoint):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(local_endpoint)
    udp_socket.setblocking(False)
    udp_socket.settimeout(1)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    return udp_socket


def fd_nonblocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags_nonblock = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags_nonblock)


def new_stun_transaction_id():
    return new_random_token(STUN_TRANSACTION_ID_LEN)


def new_random_token(length):
    chr_id = [
        random.choice(string.hexdigits)
        for _ in range(length * 2)
    ]
    hex_id = ''.join(chr_id)
    bin_id = binascii.a2b_hex(hex_id)
    return bin_id


def stun_new_header(message_type, magic_cookie, message_tid, message_data):
    # https://tools.ietf.org/html/rfc5389#section-6
    # - 16bits: message type
    # - 16bits: message length
    # - 32bits: magic cookie
    # - 96bits: transaction id
    if not isinstance(message_data, bytes):
        raise ValueError('data must be of the type {}', bytes.__name__)

    message_length = len(message_data)
    if message_length >= STUN_MAXIMUM_LENGTH:
        raise ValueError('data exeeceds maximum length of 65535 bytes')

    if len(message_tid) != STUN_TRANSACTION_ID_LEN:
        raise ValueError('transaction id must have length of {}'.format(
            STUN_TRANSACTION_ID_LEN,
        ))

    header = struct.pack(
        STUN_FORMAT_HEADER,
        message_type,
        len(message_data),
        magic_cookie,
        message_tid,
    )

    return header


def new_stun_empty_message():
    stun_attributes = b''
    stun_tid = new_stun_transaction_id()

    stun_header = stun_new_header(
        STUN_BINDING_REQUEST,
        STUN_MAGIC_COOKIE,
        stun_tid,
        stun_attributes,
    )

    return stun_header


def stun_parse_header(data):
    type_, len_, magic_cookie, transaction_id = struct.unpack_from(STUN_FORMAT_HEADER, data)
    return StunResponseHeader(type_, len_, magic_cookie, transaction_id)


def stun_unpack_attribute(data, offset):
    # https://tools.ietf.org/html/rfc5389#section-15
    # - 16bits: attribute type
    # - 16bits: attribute length
    # - variable: attribute value
    base = offset + 4
    type_, len_ = struct.unpack_from(STUN_FORMAT_ATTRIBUTE, data, offset)

    return (type_, data[base:base + len_])


def stun_parse_mapped_address(attribute):
    # https://tools.ietf.org/html/rfc5389#section-15.1
    # - 8bits: zeroed-out
    # - 8bits: family type
    # - 16bits: port
    # - 32bits: address IPv4 OR 64bits: adddress IPv6
    _, family, port = struct.unpack_from(STUN_FORMAT_MAPPED_ADDRESS, attribute)

    valid_ipv4 = family == STUN_IPv4_FAMILY and len(attribute) == 8
    valid_ipv6 = family == STUN_IPv6_FAMILY and len(attribute) == 12

    if valid_ipv4 or valid_ipv6:
        packed_address = attribute[STUN_ATTRIBUTE_HEADER_LENGTH:]
        address = socket.inet_ntoa(packed_address)
        result = StunMappedAddress(packed_address, address, port)

    else:
        result = None

    return result


def stun_parse_xor_mapped_address(attribute, magic_cookie):
    # https://tools.ietf.org/html/rfc5389#section-15.2
    # - 8bits: zeroed-out
    # - 8bits: family type
    # - 16bits: port
    # - 32bits: address IPv4 OR 64bits: adddress IPv6
    _, family, xor_port = struct.unpack_from('>cch', attribute)
    port = xor_port ^ magic_cookie

    valid_ipv4 = family == STUN_IPv4_FAMILY and len(attribute) == STUN_ATTRIBUTE_HEADER_LENGTH + 4
    valid_ipv6 = family == STUN_IPv6_FAMILY and len(attribute) == STUN_ATTRIBUTE_HEADER_LENGTH + 8

    if valid_ipv4 or valid_ipv6:
        xor_packed_address = attribute[STUN_ATTRIBUTE_HEADER_LENGTH:]
        packed_address = xor_packed_address ^ magic_cookie
        address = socket.inet_ntoa(packed_address)
        result = StunMappedAddress(packed_address, address, port)

    else:
        result = None

    return result


def stun_parse(data):
    header = stun_parse_header(data)
    attributes = []

    offset = STUN_HEADER_LENGTH
    while offset < header.length:
        type_, attribute = stun_unpack_attribute(data, offset)

        if type_ == STUN_ATTRIBUTE_MAPPED_ADDRESS:
            mapped = stun_parse_mapped_address(attribute)
            attributes.append(mapped)

        elif type_ == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
            mapped = stun_parse_xor_mapped_address(attribute, header.magic_cookie)
            attributes.append(mapped)

        else:
            attributes.append(StunAttribute(type_, attribute))

        offset += STUN_ATTRIBUTE_HEADER_LENGTH + len(attribute)

    if header.message_type == STUN_BINDING_ERROR:
        result = StunResponseError(attributes)

    elif header.message_type == STUN_BINDING_RESPONSE:
        result = StunResponseSuccess(attributes)

    return result


def poll_register(pollster, fd, readable, writable, accepting):
    flags = 0

    if readable:
        flags |= select.POLLIN | select.POLLPRI

    # accepting sockets should not be writable
    if writable and not accepting:
        flags |= select.POLLOUT

    if flags:
        flags |= select.POLLERR | select.POLLHUP | select.POLLNVAL
        pollster.register(fd, flags)


def app_nat_test(event, app_state, app_config):
    """ An application to test NAT connectivity. """

    # Init: query this node public ip/port pair from multiple stun servers
    if app_state is None and event is Init:
        local_endpoint = app_config['local_endpoint']
        message = new_stun_empty_message()

        data = [
            {endpoint: [message]}
            for endpoint in app_config['stun_endpoint_list']
        ]

        identifier = 1
        app_state = {
            'remote_endpoint': None,
            'tokens': [],
            'stun': {
                'identifier': identifier,
                'count': 0,
                'external_endpoint': {
                    'address': None,
                    'port': None,
                },
            },
        }
        action_list = [UDPNewSocket(identifier, local_endpoint, data)]

    elif isinstance(event, UDPReceive):
        if event.identifier == app_state['stun']['identifier']:
            result = stun_parse(event.data)

            if isinstance(result, StunResponseSuccess):
                for attribute in result.attributes:
                    if isinstance(attribute, StunMappedAddress):
                        endpoint = {'address': attribute.address, 'port': attribute.port}
                        break

                # Fail if the host/port differs because the NAT is *symmetric*
                if app_state['stun']['external_endpoint']['address'] != endpoint['address']:
                    app_state = None
                    action_list = [Exit(1, 'network is symmetric')]

                elif app_state['stun']['external_endpoint']['port'] != endpoint['port']:
                    app_state = None
                    action_list = [Exit(1, 'network is symmetric')]

                else:
                    app_state['stun']['external_endpoint'] = endpoint
                    app_state['stun']['count'] += 1
                    action_list = [ASK_REMOTEENDPOINT]

    elif isinstance(event, StdinReceive):
        if ':' in event.data:
            host, port = event.data.split(':')
            port = port.strip()

            try:
                socket.inet_aton(host)
            except socket.error:
                action_list = [ASK_REMOTEENDPOINT]
            else:
                if not port.isdigit():
                    action_list = [ASK_REMOTEENDPOINT]
                else:
                    app_state['remote_endpoint'] = (host, int(port))
                    token = new_random_token(10)
                    app_state['tokens'].append(token)
                    send = UDPSend(app_state['remote_endpoint'], token)
                    timer_new = TimerNew()
                    action_list = [send, timer_new]

        else:
            action_list = [ASK_REMOTEENDPOINT]

    return (app_state, action_list)


def udp_push_data(sock, fd, databuffer):
    socket_buffer = databuffer.get(fd)

    if socket_buffer is None:
        return databuffer

    # push data until the socket is full or the buffer is depleated
    # - if the socket is full an exception is raised to exit the loop
    # - if the data is depleated the while bellow exits
    remove = []
    try:
        for remote_endpoint in socket_buffer:
            data_to_send = socket_buffer[remote_endpoint]

            while data_to_send:
                data = data_to_send[0]

                # this either works or raise EWOULDBLOCK
                bytes_sent = sock.sendto(data, remote_endpoint)

                if len(data) == bytes_sent:
                    data_to_send.pop()
                else:
                    data_to_send[0] = data[bytes_sent:]

            # remove the empty data_to_send from the buffer
            remove.append(remote_endpoint)

    except socket.error as why:
        # UDP is connectionless
        # if why.args[0] in asyncorec._DISCONNECTED:
        #     handle_close()

        if why.args[0] != errno.EWOULDBLOCK:
            raise

    for remote_endpoint in remove:
        del socket_buffer[remote_endpoint]

    return databuffer


def react(event, state):
    application = state.application
    new_app_state, action_list = application.function(
        event,
        application.state,
        application.config,
    )
    application.state = new_app_state

    for action in action_list:
        if isinstance(action, UDPNewSocket):
            local_endpoint = action.local_endpoint
            data = action.endpoints_to_datum

            udp_socket = new_udp_socket(local_endpoint)
            poll_register(
                state.pollster,
                udp_socket,
                readable=True,
                writable=True,
                accepting=False,
            )

            fd = udp_socket.fileno()
            state.databuffer[fd] = data
            state.applicationid_to_fd[action.identifier] = fd
            state.fd_to_applicationid[fd] = action.identifier
            udp_push_data(udp_socket, fd, state.databuffer)

        elif isinstance(action, InputOneLine):
            state.input = action
            print(action.prompt)

        elif isinstance(action, Exit):
            print(action.message)
            sys.exit(action.result)

        elif isinstance(action, UDPSend):
            fd = state.applicationid_to_fd[action.identifier]

            if fd in state.databuffer:
                state.databuffer.append(data)
            else:
                state.databuffer[fd] = [data]

            udp_push_data(udp_socket, fd, state.databuffer)

        elif isinstance(action, TimerNew):
            timer = Timer(action.interval_ms)
            state.pollster.remote_endpoint(timer)
            state.applicationid_to_timer[action.identifier] = timer

        elif isinstance(action, TimerCancel):
            timer = state.applicationid_to_timer[action.identifier]
            state.pollster.unregister(timer)

        # else:
        #     outfd, outgoing_raw, outgoing_endpoint = action[0]
        #     if outgoing_endpoint not in state.databuffer:
        #         state.databuffer[outfd][outgoing_endpoint] = [outgoing_raw]
        #     else:
        #         state.databuffer[outfd][outgoing_endpoint].append(outgoing_raw)
        #     udp_push_data(sock, outfd, state.databuffer)

    return state


def loop(application):
    """ Top level loop that reacts to ready events from polling file
    descriptors.
    """
    fd_nonblocking(sys.stdin)
    stdinfd = sys.stdin.fileno()

    databuffer = {}
    pollster = select.poll()
    fd_to_applicationid = {}
    fd_to_socket = {}

    state = React(
        pollster,
        databuffer,
        fd_to_applicationid,
        fd_to_socket,
        application,
    )

    state = react(Init, state)

    while True:
        ready = pollster.poll()

        for fd, event in ready:
            # process incoming events
            if event & select.POLLIN:
                if fd in state.fd_to_socket:
                    sock = state.fd_to_socket[fd]
                    incoming_raw, remote_endpoint = sock.recvfrom(8192)
                    identifier = state.fd_to_applicationid[fd]
                    event = UDPReceive(identifier, remote_endpoint, incoming_raw)
                    state = react(event, state)

                if fd == stdinfd:
                    incoming_raw = sys.stdin.readline()
                    event = StdinReceive(incoming_raw)
                    state = react(event, state)

            # send buffered data out
            if event & select.POLLOUT:
                sock = state.fd_to_socket[fd]
                udp_push_data(sock, fd, databuffer)

            # handle priority events
            if event & select.POLLPRI:
                err = fd.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)

                if err != 0:
                    raise RuntimeError('select reported an error with one of the sockets')
                else:
                    raise RuntimeError('unexpected priority event')

            # UDP is connectionless
            # if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
            #     handle_close()


# wait for user input
# once the user inform the other node endpoint:
# - find the best timeout
#  - try communicating with the node
#  - if it works:
#    - try to figure out if communication works near the end of the retry timeout
#    - if it does, increase until it fails
#    - if it doesn't, decrease until it works
