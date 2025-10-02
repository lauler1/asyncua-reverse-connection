from typeguard import typechecked, install_import_hook # Type annotation check
# install_import_hook('asyncua.common.instantiate_util') # Check for type in all app

from typing import Optional

import sys
import asyncio
import socket
import logging
from urllib.parse import urlparse, urlunparse
from asyncua import ua, Server
from asyncua.server.binary_server_asyncio import BinaryServer, OPCUAProtocol
from asyncua.server.internal_server import InternalServer
from asyncua.common.connection import TransportLimits
from asyncua.client.ua_client import UaClient, UASocketProtocol
from asyncua.crypto import uacrypto
from asyncua.common.shortcuts import Shortcuts
from asyncua.crypto import security_policies
import struct
import traceback

from asyncua import Client

sys.path.insert(0, "lib")
from import_model import *
# from analyze_model import *

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

__all__ = ['ReverseServer', 'ReverseClient']


##############################################################################
#
# Helper functions for Debugging
#
##############################################################################
from colorama import init, Fore, Style
init()
def printrgb(*texts: str, color: Fore = Fore.CYAN):
    """
    Prints a text (or multiple texts) with a specific color.
    
    texts: One or more texts
    color: Color option.  Default `Fore.CYAN`.
    
    Color options:
        Fore.RED
        Fore.GREEN
        Fore.YELLOW
        Fore.BLUE
        Fore.CYAN
        Fore.MAGENTA
        Fore.WHITE
        Fore.BLACK

        TODO in future: Can also considered:
            Back.RED for background color
            Style.BRIGHT, Style.DIM, Style.NORMAL for text style
            colorama doesn't include a true "gray" — but it can be simulated using:
                Fore.BLACK with Style.BRIGHT → appears as gray on most terminals.
    """
    print(color, end="")
    for text in texts:
        print(text, end=" ")
    print(Style.RESET_ALL)

def parse_reverse_hello_message(data):
    """
    Helper function for debugging.
    It parses a binary message of type "Reverse Hello" (RHE).
    In case of parsinf error, is raises a `ValueError` exception.
    See: https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1
    
    data: Raw binary  data received or to be sent wrogh the socket.
    returns: A dictionary contained the decoded fields.
    """
    if len(data) < 24:
        raise ValueError("Incomplete message")

    header = data[:4]
    if header != b'RHEF':
        raise ValueError("Invalid header")
        
    tot_lenth = struct.unpack('<I', data[4:8])[0]
    if len(data) != tot_lenth:
        raise ValueError(f"Wrong size, len(data)={len(data)}, tot_lenth={tot_lenth}")

    # Parse the ServerUri string
    # Assume next 4 bytes is the length of the string
    if len(data) < 12:
        raise ValueError("Missing ServerUri length")

    uri_length = struct.unpack('<I', data[8:12])[0]

    if len(data) < 8 + uri_length:
        raise ValueError(f"Incomplete EndpointUri, url_length={uri_length}, len(data)={len(data)}")

    offset = 12+uri_length
    server_uri = data[12:offset].decode('utf-8')

    # Parse the EndpointUrl string
    # Assume next 4 bytes is the length of the string
    if len(data) < offset + 4:
        raise ValueError("Missing EndpointUrl length")

    url_length = struct.unpack('<I', data[offset:offset + 4])[0]
    offset = offset + 4

    if len(data) < offset + url_length:
        raise ValueError(f"Incomplete EndpointUrl, url_length={url_length}, len(data)={len(data)}")

    endpoint_url = data[offset:offset+url_length].decode('utf-8')

    return {
        'ServerUri': server_uri,
        'EndpointUrl': endpoint_url
    }

def parse_hello_message(data):
    """
    Helper function for debugging.
    It parses a binary message of type "Hello" (HEL).
    In case of parsinf error, is raises a `ValueError` exception.
    See: https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1
    
    data: Raw binary  data received or to be sent wrogh the socket.
    returns: A dictionary contained the decoded fields.
    """
    if len(data) < 24:
        raise ValueError("Incomplete message")

    header = data[:4]
    if header != b'HELF':
        raise ValueError("Invalid header")
        
    tot_lenth = struct.unpack('<I', data[4:8])[0]
    if len(data) != tot_lenth:
        raise ValueError(f"Wrong size, len(data)={len(data)}, tot_lenth={tot_lenth}")

    # Parse the 5 UInt32 fields (20 bytes total)
    fields = struct.unpack('<5I', data[8:28])
    protocol_version, recv_buf_size, send_buf_size, max_msg_size, max_chunk_count = fields

    # Parse the EndpointUrl string
    # Assume next 4 bytes is the length of the string
    if len(data) < 32:
        raise ValueError("Missing EndpointUrl length")

    url_length = struct.unpack('<I', data[28:32])[0]

    if len(data) < 32 + url_length:
        raise ValueError(f"Incomplete EndpointUrl, url_length={url_length}, len(data)={len(data)}")

    endpoint_url = data[32:32+url_length].decode('utf-8')

    return {
        'ProtocolVersion': protocol_version,
        'ReceiveBufferSize': recv_buf_size,
        'SendBufferSize': send_buf_size,
        'MaxMessageSize': max_msg_size,
        'MaxChunkCount': max_chunk_count,
        'EndpointUrl': endpoint_url
    }

def parse_ack_message(data):
    """
    Helper function for debugging.
    It parses a binary message of type "Acknowledge" (ACK).
    In case of parsinf error, is raises a `ValueError` exception.
    See: https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1
    
    data: Raw binary  data received or to be sent wrogh the socket.
    returns: A dictionary contained the decoded fields.
    """
    if len(data) < 24:
        raise ValueError("Incomplete ACK message")

    header = data[:4]
    if header != b'ACKF':
        raise ValueError("Invalid ACK header")

    tot_lenth = struct.unpack('<I', data[4:8])[0]
    if len(data) != tot_lenth:
        raise ValueError(f"Wrong size, len(data)={len(data)}, tot_lenth={tot_lenth}")
        
    # Parse the 5 UInt32 fields (20 bytes)
    fields = struct.unpack('<5I', data[8:28])
    protocol_version, recv_buf_size, send_buf_size, max_msg_size, max_chunk_count = fields

    return {
        'ProtocolVersion': protocol_version,
        'ReceiveBufferSize': recv_buf_size,
        'SendBufferSize': send_buf_size,
        'MaxMessageSize': max_msg_size,
        'MaxChunkCount': max_chunk_count
    }

def parse_error_message(data):
    """
    Helper function for debugging.
    It parses a binary message of type "Error" (ERR).
    In case of parsinf error, is raises a `ValueError` exception.
    See: https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1
    
    data: Raw binary  data received or to be sent wrogh the socket.
    returns: A dictionary contained the decoded fields.
    """
    if len(data) < 8:
        raise ValueError("Incomplete error message")

    header = data[:4]
    if header != b'ERRF':
        raise ValueError("Invalid error header")

    tot_lenth = struct.unpack('<I', data[4:8])[0]
    if len(data) != tot_lenth:
        raise ValueError(f"Wrong size, len(data)={len(data)}, tot_lenth={tot_lenth}")

    # Parse the Error code (UInt32)
    error_code = struct.unpack('<I', data[8:12])[0]

    # Parse the Reason string
    if len(data) < 16:
        raise ValueError("Missing Reason length")

    reason_length = struct.unpack('<I', data[12:16])[0]

    if len(data) < 16 + reason_length:
        raise ValueError("Incomplete Reason string")

    reason = data[16:16+reason_length].decode('utf-8')

    return {
        'Error': error_code,
        'Reason': reason
    }

class TransportWrapper():
    """
    Helper class for debugging.
    It wraps the `transport` class returned by `asyncio.Protocol.connection_made()`, which is the socket used by the asyncua.
    It intercept all the transport methods used by asyncua in order to debug the content.
    """
    def __init__(self, transport):
        """
        Construct this wrapper with the original transport.
        """
        self._transport = transport

    def get_extra_info(self, info):
        """
        Wraps the transport `get_extra_info` method.
        """
        printrgb("TransportWrapper.get_extra_info()")
        return self._transport.get_extra_info(info)
    
    def close(self):
        """
        Wraps the transport `close` method.
        """
        printrgb("TransportWrapper.close()")
        self._transport.close()
    
    def write(self, data): 
        """
        Wraps the transport `write` method.
        """
        printrgb("TransportWrapper.write()")
        printrgb(f"    Raw data sent ({len(data)} bytes):")
        # printrgb( "        hexa:", ' '.join(f'{b:02x}' for b in data))
        # printrgb( "        ascii: ", pretty_print_bytes(data))
        # Check if the first 4 bytes match 'HELF'
        if data[:4] == b'HELF':
            printrgb("        HEL Message: ", parse_hello_message(data))
        elif data[:4] == b'ACKF':
            printrgb("        ACK Message: ", parse_ack_message(data))
        elif data[:4] == b'ERRF':
            printrgb("        RR Message: ", parse_error_message(data))
        elif data[:4] == b'RHEF':
            printrgb("        RHE Message: ", parse_reverse_hello_message(data))

        # traceback.print_stack()
        # printrgb("<<<<<<<<<<<<<<<<<<<<<<<<<<")

        self._transport.write(data)

def pretty_print_bytes(data: bytes) -> str:
    """
    Print the bytes of data as ASCII when possible or as hex otherwise.
    data: 
    """
    result = []
    for b in data:
        if 32 <= b <= 126:  # Printable ASCII range
            result.append(chr(b))
        else:
            result.append(f'\\x{b:02x}')
    return ''.join(result)

##############################################################################
#
# Reverse Server (Connector socket) wrappers.
#
##############################################################################

def build_reverse_hello(server_uri: str, endpoint_url: str) -> bytes:
    """
    Creates an OPC UA Reverse Hello message ("RHE" + "F") with the respectives server_uri and endpoint_url.
    See: https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1
    
    server_uri: The ApplicationUri of the Server which sent the Message.
    endpoint_url: The URL of the Endpoint which the Client uses when establishing the SecureChannel.
    returns: Raw bytes of the message ready to be sent through the socket
    """
    message_type = b'RHEF'

    # Encode strings as UTF-8 with length prefix (UInt32)
    def encode_string(s: str) -> bytes:
        encoded = s.encode('utf-8')
        lenth = len(encoded)
        return struct.pack('<I', lenth) + encoded

    # Encode the body
    body = encode_string(server_uri) + encode_string(endpoint_url)

    # Total message size = header (8 bytes) + body
    message_size = 8 + len(body)

    # Build header: message_type + message_size (UInt32, little-endian)
    header = message_type + struct.pack('<I', message_size)

    # Return the full message
    return header + body

# Wrapper for OPCUAProtocol
class ReverseOPCUAProtocol(OPCUAProtocol):
    """
    Instantiated for every connection.
    """
    def __init__(self, iserver: InternalServer, policies, clients, closing_tasks, limits: TransportLimits, timeout: float = 1.0):
        super().__init__(iserver, policies, clients, closing_tasks, limits)
        self.timeout = timeout

    def connection_made(self, transport):
        printrgb("ReverseOPCUAProtocol.connection_made")
        _transport = TransportWrapper(transport)
        super().connection_made(_transport)

    def data_received(self, data):
        printrgb("ReverseOPCUAProtocol.data_received")
        printrgb(f"    Raw data received ({len(data)} bytes):")
        printrgb( "        hexa:", ' '.join(f'{b:02x}' for b in data))
        printrgb( "        ascii: ", pretty_print_bytes(data))

        # Check if the first 4 bytes match 'HELF'
        if data[:4] == b'HELF':
            printrgb("        HEL Message: ", parse_hello_message(data))
        elif data[:4] == b'ACKF':
            printrgb("        ACK Message: ", parse_ack_message(data))
        elif data[:4] == b'ERRF':
            printrgb("        ERR Message: ", parse_error_message(data))
        elif data[:4] == b'RHEF':
            printrgb("        RHE Message: ", parse_reverse_hello_message(data))

        super().data_received(data)

    def connection_lost(self, exc):
        printrgb("ReverseOPCUAProtocol.connection_lost")
        super().connection_lost(exc)
        raise SystemExit("Exiting now")

    async def send_reverse_hello(self, server_uri: str, endpoint_url: str, max_messagesize: int = 0, max_chunkcount: int = 0):
        printrgb(f"ReverseOPCUAProtocol.send_reverse_hello uri='{server_uri}' url='{endpoint_url}'")
        ip, port = self.transport.get_extra_info('sockname')
        data = build_reverse_hello(server_uri, endpoint_url)
        self.transport.write(data)


# Wrapper for BinaryServer
class ReverseBinaryServer(BinaryServer):
    def __init__(self, internal_server: InternalServer, hostname, port, limits: TransportLimits, server_uri: str, endpoint_url: str, timeout: float = 1.0, remote_hostname: str = "127.0.0.1", remote_port: int = 4840):
        super().__init__(internal_server, hostname, port, limits)
        self._timeout = timeout
        self.protocol = None
        self.server_uri = server_uri
        self.endpoint_url = endpoint_url
        self.remote_hostname = remote_hostname
        self.remote_port = remote_port

    def _make_protocol(self):
        """Protocol Factory"""

        print ("ReverseBinaryServer._make_protocol")
        self.protocol = ReverseOPCUAProtocol(
            iserver=self.iserver,
            policies=self._policies,
            clients=self.clients,
            closing_tasks=self.closing_tasks,
            limits=self.limits,
        )
        
        return self.protocol

    async def start(self):
        """Connect to server socket."""

        print (f"ReverseBinaryServer.start create_connection to '{self.remote_hostname}:{self.remote_port}'")
        self.logger.info("opening reverse connection")
        self._closing = False
        # Timeout the connection when the server isn't available
        await asyncio.wait_for(
            asyncio.get_running_loop().create_connection(self._make_protocol, self.remote_hostname, self.remote_port), self._timeout
        )
        print ("ReverseBinaryServer.start.create_connection -> send_reverse_hello")
        await self.protocol.send_reverse_hello(self.server_uri, self.endpoint_url)

class ReverseServer(Server):
    """
    High level reverse-connection server to connect to an OPC-UA reverse-connection client.
    Reverse server wrapper for asyncua `Server`.
    This is the main class used to create a reverse-connection server.
    """
    def __init__(self, iserver: InternalServer = None, user_manager=None, timeout: float = 1.0, remote_hostname: str = "127.0.0.1", remote_port: int = 4840, sec_chann_endpoint_url: str = None):
        """
        Creates the reverse server. This constructor is a wrapper for the asyncua `Server` constructor.
        iserver: An `InternalServer` instance. The same used by the asyncua Server. Default None.
        user_manager: Instance of one of the classes in asyncua.server.users. An `InternalServer` instance. The same used by the asyncua Server. Default None.
        timeout: Timeout in seconds to create a connection. Used internally by the ReverseBinaryServer. Default 1s.
        remote_hostname: A string containing the remote IP address or hostname to which the reverse connection should be connected.
        remote_port: The remote port number to which the reverse connection should be connected.
        sec_chann_endpoint_url: The endpoint URL that the client uses when establishing the SecureChannel. It is sent via a Reverse Hello message. If None, it will use its own endpoint, but replacing the IP 0.0.0.0 with localhost. Typically, this URL is configured on the client as if making a direct connection.
        """
        
        super().__init__(iserver, user_manager)  # Initialize base class
        self.timeout = timeout
        self.remote_hostname = remote_hostname #"sfd.infragrid.org"
        self.remote_port = remote_port
        self._sec_chann_endpoint_url = sec_chann_endpoint_url
        # self.endpoint = urlparse("opc.tcp://0.0.0.0:4840/freeopcua/server/")
        print (f"ReverseServer.__init__ {self.endpoint.geturl()}")

    async def start(self):
        """
        Start the connection. This method is a wrapper for asyncua `Server.start` method.
        This function is called by `async def __aenter__(self):` defined in the base `Server` class.
        `__aenter__` is called when Server enters in a `async with` block. E.g.: `async with server:`.
        """
        
        # print (f"\n ReverseServer.start {self.endpoint.geturl()} ^^^^^^^^^^^^^^^^^^ \n")
        # print (f"\n ReverseServer.start {self.endpoint} ^^^^^^^^^^^^^^^^^^ \n")
        if self.iserver.certificate is not None:
            # Log warnings about the certificate
            uacrypto.check_certificate(self.iserver.certificate, self._application_uri, socket.gethostname())
        await self._setup_server_nodes()
        await self.iserver.start()
        try:
            ipaddress, port = self._get_bind_socket_info()
            # !!! This is the only change !!!
            
            _endpoint_url = self._sec_chann_endpoint_url # "opc.tcp://NB105CG52039VY:4840/" # self.endpoint.geturl()
            if not _endpoint_url: # Then replace the ip of the endpoint by the hostname of the current application.
                _endpoint = self.endpoint
                # Replace hostname (netloc)
                new_hostname = socket.gethostname()
                # If the original URL has a port, preserve it
                port = _endpoint.port
                new_netloc = f"{new_hostname}:{port}" if port else new_hostname
                # Create new URL with updated netloc
                new_url = _endpoint._replace(netloc=new_netloc)
                _endpoint_url = urlunparse(new_url)
            self.bserver = ReverseBinaryServer(self.iserver, ipaddress, port, self.limits, self._application_uri, _endpoint_url, self.timeout, self.remote_hostname, self.remote_port) # BinaryServer(self.iserver, ipaddress, port, self.limits)
            self.bserver.set_policies(self._policies)
            await self.bserver.start()
        except Exception as exp:
            _logger.exception("%s error starting server", self)
            await self.iserver.stop()
            raise exp
        else:
            _logger.debug("%s server started", self)

##############################################################################
#
# Reverse Client (Listener socket) wrappers.
#
##############################################################################
# Wrapper for UASocketProtocol
class ReverseUASocketProtocol(UASocketProtocol):
    """
    Handle socket connection and send ua messages.
    Timeout is the timeout used while waiting for an ua answer from server.
    """
    def __init__(
        self,
        on_rev_hello_response, 
        timeout: float = 1,
        security_policy: security_policies.SecurityPolicy = security_policies.SecurityPolicyNone(),
        limits: TransportLimits = None,
    ):
        super().__init__(timeout, security_policy, limits)  # Initialize base class
        self._transport = None
        self.rev_hello_data = None
        self.rev_hello_received = on_rev_hello_response

    def connection_made(self, transport: asyncio.Transport):  # type: ignore[override]
        printrgb("ReverseUASocketProtocol.connection_made")
        self._transport = TransportWrapper(transport)
        # super().connection_made(_transport)

    def connection_lost(self, exc: Optional[Exception]):
        printrgb("ReverseUASocketProtocol.connection_lost")
        super().connection_lost(exc)

    def data_received(self, data: bytes) -> None:
        printrgb("ReverseUASocketProtocol.data_received")

        printrgb(f"    Raw data received ({len(data)} bytes):")
        printrgb( "        hexa:", ' '.join(f'{b:02x}' for b in data))
        printrgb( "        ascii: ", pretty_print_bytes(data))

        # Check if the first 4 bytes match 'HELF'
        if data[:4] == b'HELF':
            printrgb("        HEL Message: ", parse_hello_message(data))
        elif data[:4] == b'ACKF':
            printrgb("        ACK Message: ", parse_ack_message(data))
        elif data[:4] == b'ERRF':
            printrgb("        ERR Message: ", parse_error_message(data))
        elif data[:4] == b'RHEF':
            printrgb("        RHE Message: ", parse_reverse_hello_message(data))

        if self.rev_hello_data: # Shall allow it only after Reverse Hello is received
            super().data_received(data)
        elif data[:4] == b'RHEF':
            self.rev_hello_data = parse_reverse_hello_message(data)
            # Workaround, pretend that the client connection start only after reverse hello is received
            self.rev_hello_received.set_result(self.rev_hello_data)
            super().connection_made(self._transport)

# Wrapper for UaClient
class ReverseUaClient(UaClient):
    def __init__(self, timeout: float = 1.0, listen_hostname: str = "127.0.0.1", listen_port: int = 4840):
        """
        :param timeout: Timout in seconds
        """
        super().__init__(timeout)  # Initialize base class
        self.listen_hostname = listen_hostname
        self.listen_port = listen_port

    async def start(self):
        """
        Connect to server socket.
        
        returns: a future used to wait for the reverse hello.
        
        """
        loop = asyncio.get_running_loop()
        on_rev_hello_response = loop.create_future()
        
        printrgb(f"ReverseUaClient.start on {self.listen_hostname}:{self.listen_port}")
        self._client = await loop.create_server(lambda: self._make_protocol(on_rev_hello_response), self.listen_hostname, self.listen_port)
        # get the port and the hostname from the created server socket
        # only relevant for dynamic port asignment (when self.port == 0)
        if self.listen_port == 0 and len(self._client.sockets) == 1:
            # will work for AF_INET and AF_INET6 socket names
            # these are to only families supported by the create_server call
            sockname = self._client.sockets[0].getsockname()
            self.listen_hostname = sockname[0]
            self.listen_port = sockname[1]
        self.logger.info("Listening on %s:%s", self.listen_hostname, self.listen_port)
        # self.cleanup_task = asyncio.create_task(self._close_task_loop())
        return on_rev_hello_response

    def _make_protocol(self, on_rev_hello_response):
        printrgb("ReverseUaClient._make_protocol")
        self.protocol = ReverseUASocketProtocol(on_rev_hello_response, self._timeout, security_policy=self.security_policy)
        self.protocol.pre_request_hook = self._pre_request_hook
        return self.protocol

    async def connect(self) -> None:
        """ Overriding UaClient.connect: Should not be used in reverse client."""
        pass

    async def connect_sessionless(self) -> None:
        """ Overriding UaClient.connect_sessionless: Should not be used in reverse client."""
        pass
 
    async def connect_socket(self, host: str, port: int):
        printrgb("ReverseUaClient.connect_socket")
        self.logger.info("opening connection")
        self._closing = False
        # Timeout the connection when the server isn't available
        await asyncio.wait_for(
            asyncio.get_running_loop().create_connection(self._make_protocol, host, port), self._timeout
        )

    def disconnect_socket(self):
        printrgb("ReverseUaClient.disconnect_socket")
        if not self.protocol:
            return
        if self.protocol and self.protocol.state == UASocketProtocol.CLOSED:
            self.logger.warning("disconnect_socket was called but connection is closed")
            return None
        self.protocol.disconnect_socket()
        self.protocol = None
        
class ReverseClient(Client):
    """
    High level reverse-connection client to connect to an OPC-UA reverse-connection server.
    Reverse client wrapper for asyncua `Client`.
    This is the main class used to create a reverse-connection client.
    """

    def __init__(self, url: str, timeout: float = 4, watchdog_intervall: float = 1.0, listen_hostname: str = "127.0.0.1", listen_port: int = 4840, reverse_hello_timeout: float | None =  None):
        """
        Creates the reverse client. This constructor is a wrapper for the asyncua `Client` constructor.
        :param url: url of the reverse server. The same used by the asyncua Client.
        :param timeout: The same used by the asyncua Client. Default 4 seconds.
        :param watchdog_intervall: The same used by the asyncua Client. Default 1 second.
        :reverse_hello_timeout: timeout to receive the initial reverse hello in seconds. Default is None (wait forever).

        """
        super().__init__(url, timeout, watchdog_intervall)  # Initialize base class

        self.listen_hostname = listen_hostname
        self.listen_port = listen_port
        self.uaclient: UaClient = ReverseUaClient(timeout, listen_hostname, listen_port)
        self.uaclient.pre_request_hook = self.check_connection
        self.nodes: Shortcuts = Shortcuts(self.uaclient)
        self.reverse_hello_timeout = reverse_hello_timeout

    async def start(self):
        """
        High level method
        Connect, create and activate session
        """

        on_rev_hello_response = await self.uaclient.start()

        # Wait for the specific message
        try:

            printrgb("ReverseClient.start")
            result = await asyncio.wait_for(on_rev_hello_response, timeout=self.reverse_hello_timeout)
            printrgb("    ReverseClient.start: Reverse Hello received")
        except asyncio.TimeoutError:
            printrgb("    ReverseClient.start: Did not receive Reverse Hello in time")
            self.disconnect_socket()
            raise

        try:
            await self.send_hello()
            await self.open_secure_channel()
            try:
                await self.create_session()
                try:
                    await self.activate_session(
                        username=self._username, password=self._password, certificate=self.user_certificate
                    )
                except Exception:
                    # clean up session
                    await self.close_session()
                    raise
            except Exception:
                # clean up secure channel
                await self.close_secure_channel()
                raise
        except Exception:
            # clean up open socket
            self.disconnect_socket()
            raise

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.disconnect()

