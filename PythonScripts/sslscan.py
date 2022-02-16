#!/usr/bin/env python

"""
Usage:
    sslscan [-v] [--threads=<n>] <host>
    sslscan info <type>
    sslscan (-h | --help)
    sslscan --version

Options:
    -h --help       Show this help screen
    --version       Show the version
    -v              Be more verbose
    --threads=<n>   Use the given number of threads (default: 5)

Info Types:
    ciphers         Ciphers supported by this version of OpenSSL
"""

from __future__ import print_function

__author__ = 'Andrew Dunham <andrew@du.nham.ca>'
__version__ = '0.0.1'

import sys
import socket
import threading
from concurrent import futures
from contextlib import contextmanager
from collections import namedtuple

from OpenSSL import SSL
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser
from cryptography.hazmat.bindings.openssl.binding import Binding as OpenSSLBinding
from docopt import docopt


binding = OpenSSLBinding()
binding_ffi = binding.ffi
binding_lib = binding.lib

SSL_METHODS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1_1', 'TLSv1_2']
INSECURE_CIPHERS = [
]


Cipher = namedtuple('Cipher', ['method', 'name', 'bits'])


def cipher_as_str(c):
    if c.bits == 'Anon':
        return "%s (Anonymous cipher)" % (c.name,)
    else:
        return "%s (%s bits)" % (c.name, c.bits)


class HostInfo(object):
    CIPHER_ACCEPTED = 0
    CIPHER_REJECTED = 1
    CIPHER_ERRORED  = 2

    def __init__(self, server, port):
        # Host information
        self.server = server
        self.port = port

        # Lock for complex operations
        self.lock = threading.Lock()

        # Format: (cipher, result)
        self.ciphers = []
        self.preferred_ciphers = {}

        self.cert_chain = None

    @property
    def address(self):
        return (self.server, self.port)

    @contextmanager
    def lock(self):
        """
        Lock the structure for use with multiple threads.
        """
        self.lock.acquire()
        yield
        self.lock.release()

    def report_cipher(self, method, cipher, bits, result):
        # For anonymous ciphers, we don't care about the key size
        if 'ADH' in cipher or 'AECDH' in cipher:
            bits = 'Anon'
        elif bits == -1:
            bits = 'Unknown'
        else:
            bits = str(bits)

        self.ciphers.append((Cipher(method, cipher, bits), result))

    def report_preferred(self, method, cipher, bits):
        # For anonymous ciphers, we don't care about the key size
        if 'ADH' in cipher or 'AECDH' in cipher:
            bits = 'Anon'
        elif bits == -1:
            bits = 'Unknown'
        else:
            bits = str(bits)

        self.preferred_ciphers[method] = Cipher(method, cipher, bits)

    @property
    def accepted_ciphers(self):
        return (x[0] for x in self.ciphers if x[1] == self.CIPHER_ACCEPTED)

    @property
    def rejected_ciphers(self):
        return (x[0] for x in self.ciphers if x[1] == self.CIPHER_REJECTED)

    @property
    def errored_ciphers(self):
        return (x[0] for x in self.ciphers if x[1] == self.CIPHER_ERRORED)

    def accepted_ciphers_for(self, method):
        return (x for x in self.accepted_ciphers if x.method == method)

    def rejected_ciphers_for(self, method):
        return (x for x in self.rejected_ciphers if x.method == method)

    def errored_ciphers_for(self, method):
        return (x for x in self.errored_ciphers if x.method == method)


def get_all_ciphers(method):
    """
    Get all ciphers supported by this version of OpenSSL.
    """
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        context = SSL.Context(ssl_method)
        context.set_cipher_list("ALL:COMPLEMENTOFALL")
        sock = SSL.Connection(context, sock)
        ciphers = sock.get_cipher_list()
    except SSL.Error:
        ciphers = []
    finally:
        sock.close()

    return ciphers


def make_request(sock, server_name):
    """
    Given an open socket, makes a simple HTTP request, parses the response, and
    returns a dictionary containing the HTTP headers that were returned by the
    server.
    """
    p = HttpParser()

    request = ('GET / HTTP/1.0\r\n' +
               'User-Agent: pySSLScan\r\n' +
               'Host: %s\r\n\r\n' % (server_name,))
    sock.write(request.encode('ascii'))

    headers = None
    while True:
        data = sock.recv(1024)
        if not data:
            break

        recved = len(data)
        nparsed = p.execute(data, recved)
        assert nparsed == recved

        if p.is_headers_complete():
            headers = p.get_headers()
            break

    return headers


def get_cipher_bits(sock):
    """
    Given a socket, gets the number of bits that the current cipher is using.
    *Very* heavily dependent on the implementation of pyOpenSSL right now. :-(
    """
    cipher = binding_lib.SSL_get_current_cipher(sock._ssl)
    if cipher == binding_ffi.NULL:
        return None

    return binding_lib.SSL_CIPHER_get_bits(cipher, binding_ffi.NULL)


def test_single_cipher(host, method, cipher):
    """
    Test to see if the server supports a given method/cipher combination.
    """
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    context = SSL.Context(ssl_method)
    context.set_cipher_list(cipher)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect(host.address)

        headers = make_request(sock, host.server)

        bits = get_cipher_bits(sock)
        host.report_cipher(method, cipher, bits, HostInfo.CIPHER_ACCEPTED)
    except SSL.Error as e:
        host.report_cipher(method, cipher, -1, HostInfo.CIPHER_FAILED)
    finally:
        sock.close()


def test_preferred_cipher(host, method):
    """
    Test what the server's preferred cipher is when a client will accept all
    ciphers.
    """
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    context = SSL.Context(ssl_method)
    context.set_cipher_list("ALL:COMPLEMENTOFALL")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect(host.address)

        headers = make_request(sock, host.server)

        preferred = sock.cipher()
        host.report_preferred(method, preferred[0], preferred[2])
    except SSL.Error as e:
        pass
    finally:
        sock.close()


def validate_cert_chain(host):
    """
    Validate the server's certificate chain.
    """
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_cipher_list("ALL:COMPLEMENTOFALL")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect(host.address)

        headers = make_request(sock, host.server)

        chain = sock.get_peer_cert_chain()
        host.cert_chain = chain
    except SSL.Error as e:
        pass
    finally:
        sock.close()


def info(arguments):
    ty = arguments['<type>']
    if ty == 'ciphers':
        for method in SSL_METHODS:
            try:
                supported_ciphers = get_all_ciphers(method)
            except ValueError:
                print("Method not supported: %s" % (method,))
                continue

            print("Method: %s" % (method,))
            print("-" * 50)
            for cipher in sorted(supported_ciphers):
                print(cipher)
            print('')

    else:
        print("Unknown info type: %s" % (ty,))


def main():
    arguments = docopt(__doc__, version=__version__)
    if arguments['info']:
        return info(arguments)

    # Get the address from the user.
    server = arguments['<host>']
    port   = 443
    if ':' in server:
        server, port = server.split(':', 1)
        port = int(port)

    threads = arguments['--threads']
    if threads is None:
        threads = 5
    else:
        threads = int(threads)

    ssl_version = SSL.SSLeay_version(SSL.SSLEAY_VERSION)
    if not isinstance(ssl_version, str):
        ssl_version = ssl_version.decode('ascii')

    print_box = lambda s, **kw: print('| ' + s.ljust(59) + '|', **kw)
    print("+" + "-" * 60 + "+")
    print_box("pySSLScan version %s" % (__version__,))
    print_box("  OpenSSL version: %s" % (ssl_version,))
    print_box("  Threads:       : %d" % (threads,))
    print_box("  Verbose:       : %s" % (bool(arguments['-v']),))
    print("+" + "-" * 60 + "+")
    print('')

    # Create host structure.
    host = HostInfo(server, port)

    # Note that this statement will wait for all executed things to finish.
    print("Scanning, please wait... ", end='')
    sys.stdout.flush()
    with futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Validate certificate chain for the server.
        executor.submit(validate_cert_chain, host)

        for method in SSL_METHODS:
            try:
                supported_ciphers = get_all_ciphers(method)
            except ValueError:
                print("Method not supported: %s" % (method,))
                continue

            # Test each individual cipher.
            for cipher in supported_ciphers:
                executor.submit(test_single_cipher, host, method, cipher)

            # Test for the preferred cipher suite for this method.
            executor.submit(test_preferred_cipher, host, method)

    print('done!\n')

    # Print results.
    for method in SSL_METHODS:
        print("Ciphers for %s:" % (method,))
        print("-" * 20)

        for cipher in sorted(host.accepted_ciphers_for(method)):
            print(' ' + cipher_as_str(cipher))

        if arguments['-v']:
            for cipher in sorted(host.rejected_ciphers_for(method)):
                print(' (rejected) ' + cipher_as_str(cipher))
            for cipher in sorted(host.errored_ciphers_for(method)):
                print(' (errored) ' + cipher_as_str(cipher))

        print('')

    print('Preferred Ciphers:')
    print('-' * 20)
    for method in SSL_METHODS:
        preferred = host.preferred_ciphers.get(method)
        if preferred is not None:
            print(" %s: %s" % (method, cipher_as_str(preferred)))
        else:
            print(" %s: None" % (method,))
    print('')

    # Lastly, print any problems found
    print('Problems:')
    print('-' * 20)

    if len(list(host.accepted_ciphers_for('SSLv2'))) > 0:
        print("- Host supports SSLv2")

    anon_ciphers = []
    weak_ciphers = []
    for method in SSL_METHODS:
        for cipher in sorted(host.accepted_ciphers_for(method)):
            if cipher.bits == 'Anon':
                anon_ciphers.append(cipher)
            elif cipher.bits == 'Unknown':
                # TODO: report?
                pass
            elif int(cipher.bits) < 128:
                weak_ciphers.append(cipher)

    if len(anon_ciphers) > 0:
        print('- Host supports anonymous cipher suites')
        for x in anon_ciphers:
            print('  - %s' % (x,))

    if len(weak_ciphers) > 0:
        print('- Host supports weak cipher suites')
        for x in weak_ciphers:
            print('  - %s' % (x,))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
