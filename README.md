
# Reverse Connection with `asyncua`

## Reverse Connection Library

This folder contains a library that adds **reverse connection** capabilities to Python’s `asyncua` library. It works by wrapping certain classes from `asyncua` for both server and client functionality, as detailed in the study section further below.

All reverse connection features are implemented in a single file: `asyncua_reverse_conn.py`.

The library includes two Python applications as examples to demonstrate and test reverse connection functionality:

- `client.py` – Reverse client example  
- `server.py` – Reverse server example

---

### `client.py` – Reverse Client Example

This script implements a simple client that **waits for a connection**. Once connected, it collects folder information from the server—specifically the IDs and names of the following folders and their respective children: `Root` and `Objects`.

After completing the data collection, the client disconnects and exits.

The main difference from a standard client is the use of the custom `ReverseClient` class instead of `asyncua.Client`.

```python
class ReverseClient(Client):
    """
    High-level reverse-connection client to connect to an OPC UA reverse-connection server.
    This is a wrapper around asyncua's `Client`.
    """

    def __init__(self, url: str, timeout: float = 4, watchdog_intervall: float = 1.0,
                 listen_hostname: str = "127.0.0.1", listen_port: int = 4840,
                 reverse_hello_timeout: float | None = None):
        """
        Initializes the reverse client.

        :param url: URL of the reverse server (same as used by asyncua Client).
        :param timeout: Connection timeout in seconds (default: 4).
        :param watchdog_intervall: Watchdog interval in seconds (default: 1).
        :param listen_hostname: Hostname to listen on (default: 127.0.0.1).
        :param listen_port: Port to listen on for reverse connections (default: 4840).
        :param reverse_hello_timeout: Timeout for receiving the initial reverse hello (default: None = wait indefinitely).
        """
```

In this example, the client specifies only the `listen_port` to enable reverse functionality.

#### Security

Security is supported. If certificates are not found in the directory, the client can generate them automatically.

⚠️ **Important:** When using security with reverse connections, the **server certificate must be manually added to the client**. This cannot be done automatically, as the client cannot fetch the server certificate via a direct connection (unlike in standard OPC UA clients). Use the `set_security` or `set_security_string` methods to configure this.

---

### `server.py` – Reverse Server Example

This server connects to a reverse client and provides a static data model defined in `config.json`. This allows the client to browse the server’s nodes.

The main difference from a standard server is the use of the custom `ReverseServer` class instead of `asyncua.Server`.

```python
class ReverseServer(Server):
    """
    High-level reverse-connection server to connect to an OPC UA reverse-connection client.
    This is a wrapper around asyncua's `Server`.
    """

    def __init__(self, iserver: InternalServer = None, user_manager=None, timeout: float = 1.0,
                 remote_hostname: str = "127.0.0.1", remote_port: int = 4840,
                 sec_chann_endpoint_url: str = None):
        """
        Initializes the reverse server.

        :param iserver: An `InternalServer` instance (optional).
        :param user_manager: User manager instance from `asyncua.server.users` (optional).
        :param timeout: Connection timeout in seconds (default: 1).
        :param remote_hostname: IP address or hostname of the reverse client.
        :param remote_port: Port number of the reverse client.
        :param sec_chann_endpoint_url: Endpoint URL used by the client to establish the SecureChannel.
                                       If None, defaults to the server’s own endpoint with IP replaced by localhost.
        """
```

The server’s data model is configured via `config.json`, which is processed by `.\lib\import_model.py`.
> 🔹 The `endpoint` configuration in the JSON is currently unused and can be ignored.

> The reason for using this import model library is because I used another project as example for the server which already used it.

#### Security

Security is also supported. If certificates are not found, the server can generate them automatically.

To enable secure reverse connections, the **client must have the server’s certificate stored locally**.

---

### `asyncua_reverse_conn.py`

This file contains all the necessary components to implement reverse connection functionality for both server and client.

It is organized into three main sections:

1. **Helper functions** for debugging. Almost all can be removed from the code.
2. **Reverse Server** (connector socket) wrappers  
3. **Reverse Client** (listener socket) wrappers

> ⚠️ **Note:** This library is intended for **testing and research purposes only**. It is **not production-ready** and does not guarantee full compliance with OPC UA specifications or the reliability required for commercial applications.

## Study

From my study with asyncua source code, the low leel tcp communication is implemented via `asyncio.Protocol`.

asyncio.Protocol is a low-level interface in Python's asyncio library used to build network clients and servers. It gives you fine-grained control over how connections are handled, compared to the higher-level StreamReader/StreamWriter API.

```bash
>grep -nri "asyncio.Protocol" .\asyncua
.\asyncua/client/ua_client.py:21:class UASocketProtocol(asyncio.Protocol):
.\asyncua/server/binary_server_asyncio.py:18:class OPCUAProtocol(asyncio.Protocol):
```

🔧 **Key Concepts of asyncio.Protocol**

You define a class that inherits from asyncio.Protocol.
This class implements methods like:
connection_made(): called when a connection is established.
data_received(): called when data is received.
connection_lost(): called when the connection is closed.

Sequence Flow of opc ua reverse connection:

Reverse Client starts and listens on a socket (e.g., port 4840).
Reverse Server initiates a TCP connection to the client.
Reverse Server sends a ReverseHello message to the client.
Reverse Client responds with a Hello message.
Secure Channel is established:

OpenSecureChannelRequest → OpenSecureChannelResponse

Session is created:

CreateSessionRequest → CreateSessionResponse
ActivateSessionRequest → ActivateSessionResponse

Client begins browsing or reading nodes from the server.

```
+----------------+           +----------------+
| Reverse Client |           | Reverse Server |
+----------------+           +----------------+
        |                            |
        |<---------------------------| 1. TCP Connect
        |<---------------------------| 2. ReverseHello
        |--------------------------->| 3. Hello
        |--------------------------->| 4. OpenSecureChannelRequest
        |<---------------------------| 5. OpenSecureChannelResponse
        |--------------------------->| 6. CreateSessionRequest
        |<---------------------------| 7. CreateSessionResponse
        |--------------------------->| 8. ActivateSessionRequest
        |<---------------------------| 9. ActivateSessionResponse
        |                            |
        |====== Secure Session Established ======|
        |                            |
        |--------------------------->| 10. Browse / Read / Write
        |<---------------------------| 11. Response
```





### asyncio.Protocol Client

On the client implementation of asyncua, the `asyncio.Protocol` is implemented by `class UASocketProtocol` (see asycua `ua_client.py:21`). It is instantiated by `class UaClient` (see asycua `ua_client.py:308` and `ua_client.py:328`).

The two places responsible for the instantiation and create connection can be seen here:

```python
class UaClient(AbstractSession):
	...
    def _make_protocol(self):
        self.protocol = UASocketProtocol(self._timeout, security_policy=self.security_policy)
        self.protocol.pre_request_hook = self._pre_request_hook
        return self.protocol
	...
    async def connect_socket(self, host: str, port: int):
        """Connect to server socket."""
        self.logger.info("opening connection")
        self._closing = False
        # Timeout the connection when the server isn't available
        await asyncio.wait_for(
            asyncio.get_running_loop().create_connection(self._make_protocol, host, port), self._timeout
        )
	...
```

The `UaClient` is instantiated by `class Client` respectively (see asycua `client.py:78`):

```python
    def __init__(self, url: str, timeout: float = 4, watchdog_intervall: float = 1.0):
		...
        self.uaclient: UaClient = UaClient(timeout)
        self.uaclient.pre_request_hook = self.check_connection
		...
        self.nodes: Shortcuts = Shortcuts(self.uaclient)
		...

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.disconnect()
	...

```

#### Extrategy to a reverse connection client

The proposal for a reverse connection client would be by writing a new `class ReverseClient` deriverd from `class Client`, where `UaClient` would be replaced by a new derived `ReverseUaClient` and `UASocketProtocol` would be replaced by a new derived `ReverseUASocketProtocol`.
`ReverseUASocketProtocol` shall be capable of receive a Reverse Hello with the uri of the application and the url of the endpoint (url of the reverse client).
Soon after the connection is stabilished, a reverse Hello is received by the reverse client. Than the communication should proced as for normal connection.

The server certificate is needed in reverse connection with security because the client cannot fetch it with direct connection. In normal client this can be fetch by the client by open a separate connection before the main client connetion is open, just to fetch it. This is done by the `set_security` and `set_security_string` functions.

### asyncio.Protocol Server

On the server implementation of asyncua, the `asyncio.Protocol` is implemented by `class OPCUAProtocol` (see asycua `binary_server_asyncio.py:18`). It is instantiated by `class BinaryServer` (see asycua `binary_server_asyncio.py:131` and `binary_server_asyncio.py:142`).

The two places responsible for the instantiation and start listening can be seen here:

```python
class BinaryServer:
	...
    def _make_protocol(self):
        """Protocol Factory"""
        return OPCUAProtocol(
            iserver=self.iserver,
            policies=self._policies,
            clients=self.clients,
            closing_tasks=self.closing_tasks,
            limits=self.limits,
        )

    async def start(self):
        self._server = await asyncio.get_running_loop().create_server(self._make_protocol, self.hostname, self.port)
        # get the port and the hostname from the created server socket
        # only relevant for dynamic port asignment (when self.port == 0)
        if self.port == 0 and len(self._server.sockets) == 1:
            # will work for AF_INET and AF_INET6 socket names
            # these are to only families supported by the create_server call
            sockname = self._server.sockets[0].getsockname()
            self.hostname = sockname[0]
            self.port = sockname[1]
        self.logger.info("Listening on %s:%s", self.hostname, self.port)
        self.cleanup_task = asyncio.create_task(self._close_task_loop())
	...
```

The `BinaryServer` is instantiated by `class Server` respectively (see asycua `server.py:493`):

```python
class Server:
	...
    async def __aenter__(self):
        await self.start()
	...
    async def start(self):
        """
        Start to listen on network
        """
        if self.iserver.certificate is not None:
            # Log warnings about the certificate
            uacrypto.check_certificate(self.iserver.certificate, self._application_uri, socket.gethostname())
        await self._setup_server_nodes()
        await self.iserver.start()
        try:
            ipaddress, port = self._get_bind_socket_info()
            self.bserver = BinaryServer(self.iserver, ipaddress, port, self.limits)
            self.bserver.set_policies(self._policies)
            await self.bserver.start()
        except Exception as exp:
            _logger.exception("%s error starting server", self)
            await self.iserver.stop()
            raise exp
        else:
            _logger.debug("%s server started", self)
	...
```

And the `Server.start` method is called by `Server.__aenter__` when entering the async event loop, e.g. in the server example below:

```python
    # setup our server
    server = Server()
    await server.init()
	...
    print("Starting async event loop!")
    async with server:
        count = 0
        while True:
		...
```

#### Extrategy to a reverse connection server

The proposal for a reverse connection server would be by writing a new `class ReverseServer` deriverd from `class Server`, where `BinaryServer` would be replaced by a new derived `ReverseBinaryServer` and `OPCUAProtocol` would be replaced by a new derived `ReverseOPCUAProtocol`.
`ReverseOPCUAProtocol` shall be capable of sending a Reverse Hello with the uri of the application and the url of the endpoint (url of the reverse client).
Soon after the connection is stabilished, a reverse Hello is sent by the reverse server. Than the communication should proced as for normal connection.


# Testing

## Endpoint for Reverse Connect to an external equipment:

- Endpoint: sfd.infragrid.org
- Port: 4840
- Supported Security Modes
    - Sign
    - SignAndEncrypt
- Supported SecurityPolicies:
    - Basic128Rsa15
    - Basic256
    - Basic256Sha256
    - Aes128Sha256RsaOaep
    - Aes256Sha256RsaPss




