from typeguard import typechecked, install_import_hook # Type annotation check
# install_import_hook('asyncua.common.instantiate_util') # Check for type in all app

import sys
import asyncio
import socket
import logging
from pathlib import Path
from asyncua import ua #, Server
from asyncua.common.methods import uamethod
from asyncua.common.instantiate_util import instantiate
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from cryptography.x509.oid import ExtendedKeyUsageOID
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto import validator
from asyncua_reverse_conn import *

sys.path.insert(0, "lib")
from import_model import *

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)
USE_TRUST_STORE = False

@uamethod
def func(parent, value):
    result = value * 2
    print(f"MyServerMethod func({parent}, {value}) -> {result}")
    return result

@typechecked
async def main():

    print("Hi!")
    
    server_cert = Path(f"server-certificate-example.der") # my_cert.der
    server_private_key = Path(f"server-private-key-example.pem") # my_key.pem

    host_name = socket.gethostname()
    server_app_uri = "urn:NB105CG52039VY:server"
    await setup_self_signed_certificate(
        server_private_key,
        server_cert,
        server_app_uri,
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
    
    # setup our server
    server = ReverseServer(remote_hostname="127.0.0.1", remote_port=4841) # "sfd.infragrid.org", "NB105CG52039VY", "127.0.0.1"
    await server.init()
    
    server.set_endpoint("opc.tcp://0.0.0.0:4840/") # opc.tcp://0.0.0.0:4840/freeopcua/server
    await server.set_application_uri(server_app_uri)
    
    server.set_security_policy(
        [
            ua.SecurityPolicyType.NoSecurity,
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Basic256Sha256_Sign,
            ua.SecurityPolicyType.Basic256_SignAndEncrypt,
            ua.SecurityPolicyType.Basic256_Sign,
        ]
    )
    
    # server.set_security_policy(
        # [
            # ua.SecurityPolicyType.NoSecurity,
            # ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            # ua.SecurityPolicyType.Basic256Sha256_Sign,
        # ]
    # )
    
    # load server certificate and private key. This enables endpoints
    # with signing and encryption.
    await server.load_certificate(str(server_cert))
    await server.load_private_key(str(server_private_key))

    if USE_TRUST_STORE:
        trust_store = TrustStore([Path("examples") / "certificates" / "trusted" / "certs"], [])
        await trust_store.load()
        validator = CertificateValidator(
            options=CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_CLIENT,
            trust_store=trust_store,
        )
    else:
        validator = CertificateValidator(
            options=CertificateValidatorOptions.EXT_VALIDATION | CertificateValidatorOptions.PEER_CLIENT
        )
    server.set_certificate_validator(validator)
    
    model = await import_server_model(server, "config.json")
    custom_idx = model["idx"]["http://yourorganisation.org/customobject/"]
    
    print("#########################")
    print(f"model['idx'] = {model["idx"]}")
    print(f"custom_idx = {custom_idx}")

    # # Instantiate LevelCrossingType (defined in eulynx.generic.bl4r3.xml) and add to LevelCrossingProductGroupSet
    # # ######################################################
    # node_level_crossing_type = server.get_node("ns=3;i=1130") # Level crossing
    # print("node_level_crossing_type = " + str(node_level_crossing_type))   
    # node_level_crossing_type_nodeid = node_level_crossing_type.nodeid
    # print("node_level_crossing_type_nodeid = " + str(node_level_crossing_type_nodeid))
    # levelCrossingProductGroupSet_obj = server.get_node("ns=3;i=5124") # levelCrossingProductGroupSet
    # # myLevelCrossing = await levelCrossingProductGroupSet_obj.add_object(3, "MyLevelCrossing", node_level_crossing_type_nodeid)
    # myLevelCrossing = await instantiate(levelCrossingProductGroupSet_obj, node_level_crossing_type, dname=ua.LocalizedText.from_string("MyLevelCrossing"))

    # # Instantiate <Controller> (defined in eulynx.generic.bl4r3.xml) and add to LevelCrossingEquipmentSet
    # # ######################################################
    # node_controller_type = server.get_node("ns=3;i=5086") # <Controller>
    # print("node_controller_type = " + str(node_controller_type))   
    # node_controller_type_nodeid = node_controller_type.nodeid
    # print("node_controller_type_nodeid = " + str(node_controller_type_nodeid))
    # levelCrossingEquipmentSet_obj = server.get_node("ns=3;i=5114") # LevelCrossingEquipmentSet
    # # myController = await levelCrossingEquipmentSet_obj.add_object(3, "MyController", node_controller_type_nodeid)
    # myLevelCrossing = await instantiate(levelCrossingEquipmentSet_obj, node_controller_type, dname=ua.LocalizedText.from_string("MyController"))

    print("Starting Loop!")
    async with server:
        count = 0
        while True:
            print(f"{count}\r", end='', flush=True)
            await asyncio.sleep(1)
            count += 1

    print("Bye!")

if __name__ == "__main__":
    # logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
    