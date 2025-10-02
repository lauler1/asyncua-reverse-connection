"""
This client will connect to a server and goes through all children nodes from `root` (i=84) and print.
"""

import asyncio
import sys
import socket
from pathlib import Path
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from cryptography.x509.oid import ExtendedKeyUsageOID
from asyncua.ua.attribute_ids import AttributeIds
from asyncua_reverse_conn import *
sys.path.insert(0, "lib")

import logging
# logging.basicConfig(level=logging.CRITICAL + 1)
#logging.basicConfig(level=logging.INFO)
# Remove all handlers from the root logger
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
# logger = logging.getLogger(__name__)

async def set_security(client):
    print("set_security:")
    cert = Path(f"client-certificate-example.der") # my_cert.der
    private_key = Path(f"client-private-key-example.pem") # my_key.pem
    
    server_cert = Path(f"server-certificate-example.der") # The server certificate is needed in reverse connection because the client cannot fetch it with direct connection

    host_name = socket.gethostname()
    client_app_uri = f"urn:hitachi:opcua:NB105CG52039VY"
    await setup_self_signed_certificate(
        private_key,
        cert,
        client_app_uri,
        host_name,
        [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
        {
            "countryName": "DE",
            "stateOrProvinceName": "BW",
            "localityName": "hitachi",
            "organizationName": "hitachi",
        },
    )
    print("setup_self_signed_certificate DONE")
    client.set_user("opcua")
    client.set_password("opcua")
    client.application_uri = client_app_uri
    
    # IMPORTANT: In reverse connection, the server certificate is important
    await client.set_security_string(f"Basic256Sha256,SignAndEncrypt,{cert},{private_key},{server_cert}")
    print("set_security DONE")

async def main():

    client = ReverseClient("opc.tcp://sfd.infragrid.org:52530/OPCUA/SFD", listen_port=4841)
    await set_security(client)
    client.session_timeout = 20000
    print("STARTING")
    async with client:
        root = client.nodes.root
        objects = client.nodes.objects
        # root_node = client.get_node("i=84") # Root: i=84, Objects: i=85, Types: i=86, Views: i=87, NamespaceArray: i=2255

        async def proc_node_and_get_all_children_recursive(curr_node):
            """
            Process current node and get all children nodes from `curr_node` and print them (id and display name).
            """
            async def get_display_name(node):
                try:
                    attr = await node.read_attribute(AttributeIds.DisplayName)
                except Exception as e:
                    return "[UNKNOWN]"
                return attr.Value.Value.Text

            node_display_name = await get_display_name(curr_node)
            print(f"    Getting node: {curr_node} {node_display_name}")
            objects_children = await curr_node.get_children()
            for child in objects_children:
                node_display_name = await get_display_name(child)
                print(f"        Getting child node: {child} {node_display_name}")

        await proc_node_and_get_all_children_recursive(root)
        await proc_node_and_get_all_children_recursive(objects)
    print("END")

if __name__ == "__main__":
    asyncio.run(main())
