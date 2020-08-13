from dummyserver.testcase import SocketDummyServerTestCase, consume_socket
from dummyserver.server import (
    DEFAULT_CERTS,
    DEFAULT_CA,
)

from urllib3.contrib.ssl import SSLTransport, SSLTransportError

import select
import pytest
import socket
import ssl


def get_server_client_ssl_contexts():
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(DEFAULT_CERTS["certfile"], DEFAULT_CERTS["keyfile"])
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(DEFAULT_CA)
    return server_context, client_context


class SingleTLSLayerTestCase(SocketDummyServerTestCase):
    """
    Uses the SocketDummyServer to validate a single TLS layer can be
    established through the SSLTransport.
    """

    @classmethod
    def setup_class(cls):
        cls.server_context, cls.client_context = get_server_client_ssl_contexts()

    def start_dummy_server(self):
        def socket_handler(listener):
            sock = listener.accept()[0]
            with self.server_context.wrap_socket(sock, server_side=True) as ssock:
                request = consume_socket(ssock)
                assert request is not None
                assert "www.testing.com" in request.decode("utf-8")

                response = b"HTTP/1.1 200 OK\r\n" b"Content-Length: 0\r\n" b"\r\n"
                ssock.send(response)
                ssock.close()

        self._start_server(socket_handler)

    def test_start_closed_socket(self):
        """ Errors generated from an unconnected socket should bubble up."""
        sock = socket.socket(socket.AF_INET)
        context = ssl.create_default_context()
        sock.close()
        with pytest.raises(OSError):
            SSLTransport(sock, context)

    def test_close_after_handshake(self):
        """ Socket errors should be bubbled up """
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(sock, self.client_context) as ssock:
            ssock.close()
            with pytest.raises(OSError):
                ssock.send(b"blaaargh")

    def test_wrap_existing_socket(self):
        """ Validates a single TLS layer can be established.  """
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            assert ssock.version() is not None
            ssock.send(
                b"GET http://www.testing.com/ HTTP/1.1\r\n"
                b"Host: www.testing.com\r\n"
                b"User-Agent: awesome-test\r\n"
                b"\r\n"
            )
            response = consume_socket(ssock)
            assert response is not None

    def test_ssl_object_attributes(self):
        """ Ensures common ssl attributes are exposed """
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            assert ssock.cipher() is not None
            assert ssock.selected_alpn_protocol() is None
            assert ssock.selected_npn_protocol() is None
            assert ssock.shared_ciphers() is not None
            assert ssock.compression() is None
            assert ssock.getpeercert() is not None

            ssock.send(
                b"GET http://www.testing.com/ HTTP/1.1\r\n"
                b"Host: www.testing.com\r\n"
                b"User-Agent: awesome-test\r\n"
                b"\r\n"
            )
            response = consume_socket(ssock)
            assert response is not None

    def test_socket_object_attributes(self):
        """ Ensures common socket attributes are exposed """
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            assert ssock.fileno() is not None
            test_timeout = 10
            ssock.settimeout(test_timeout)
            assert ssock.gettimeout() == test_timeout
            ssock.send(
                b"GET http://www.testing.com/ HTTP/1.1\r\n"
                b"Host: www.testing.com\r\n"
                b"User-Agent: awesome-test\r\n"
                b"\r\n"
            )
            response = consume_socket(ssock)
            assert response is not None


class SocketProxyDummyServer(SocketDummyServerTestCase):
    """
    Simulates a proxy that performs a simple I/O loop on client/server
    socket.
    """

    def __init__(self, destination_server_host, destination_server_port):
        self.destination_server_host = destination_server_host
        self.destination_server_port = destination_server_port
        self.server_context, self.client_context = get_server_client_ssl_contexts()

    def start_proxy_handler(self):
        """
        Socket handler for the proxy. Terminates the first TLS layer and tunnels
        any bytes needed for client <-> server communicatin.
        """

        def proxy_handler(listener):
            sock = listener.accept()[0]
            with self.server_context.wrap_socket(sock, server_side=True) as client_sock:
                upstream_sock = socket.create_connection(
                    (self.destination_server_host, self.destination_server_port)
                )
                self._read_write_loop(client_sock, upstream_sock)
                upstream_sock.close()

        self._start_server(proxy_handler)

    def _read_write_loop(self, client_sock, server_sock, chunks=65536):
        inputs = [client_sock, server_sock]
        output = [client_sock, server_sock]

        while inputs:
            readable, writable, exception = select.select(inputs, output, inputs)
            for s in readable:
                read_socket, write_socket = None, None
                if s == client_sock:
                    read_socket = client_sock
                    write_socket = server_sock
                else:
                    read_socket = server_sock
                    write_socket = client_sock

                # Ensure buffer is not full before writting
                if write_socket in writable:
                    b = read_socket.recv(chunks)
                    write_socket.send(b)

            if exception:
                # Error ocurred with either of the sockets, time to
                # wrap up.
                break


class TlsInTlsTestCase(SocketDummyServerTestCase):
    """
    Creates a TLS in TLS tunnel by chaining a 'SocketProxyDummyServer' and a
    `SocketDummyServerTestCase`.

    Client will first connect to the proxy, who will then proxy any bytes send
    to the destination server. First TLS layer terminates at the proxy, second
    TLS layer terminates at the destination server.
    """

    @classmethod
    def setup_class(cls):
        cls.server_context, cls.client_context = get_server_client_ssl_contexts()

    @classmethod
    def start_proxy_server(cls):
        # Proxy server will handle the first TLS connection and create a
        # connection to the destination server.
        cls.proxy_server = SocketProxyDummyServer(cls.host, cls.port)
        cls.proxy_server.start_proxy_handler()

    @classmethod
    def teardown_class(cls):
        if hasattr(cls, "proxy_server"):
            cls.proxy_server.teardown_class()

    @classmethod
    def start_destination_server(cls):
        """
        Socket handler for the destination_server. Terminates the second TLS
        layer and send a basic HTTP response.
        """

        def socket_handler(listener):
            sock = listener.accept()[0]
            with cls.server_context.wrap_socket(sock, server_side=True) as ssock:
                request = consume_socket(ssock)
                assert request is not None
                assert "www.testing.com" in request.decode("utf-8")

                response = b"HTTP/1.1 200 OK\r\n" b"Content-Length: 0\r\n" b"\r\n"
                ssock.send(response)
                ssock.close()

        cls._start_server(socket_handler)

    def test_tls_in_tls_tunnel(self):
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with SSLTransport(
                proxy_sock, self.client_context, server_hostname="localhost"
            ) as destination_sock:
                assert destination_sock.version() is not None
                destination_sock.send(
                    b"GET http://www.testing.com/ HTTP/1.1\r\n"
                    b"Host: www.testing.com\r\n"
                    b"User-Agent: awesome-test\r\n"
                    b"\r\n"
                )
                response = consume_socket(destination_sock)
                assert response is not None
                assert "200" in response.decode("utf-8")

    def test_wrong_sni_hint(self):
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with pytest.raises(SSLTransportError):
                SSLTransport(
                    proxy_sock, self.client_context, server_hostname="veryverywrong"
                )
