import cbor2
import datetime
import hashlib
import secrets
import uuid

from pycose.headers import Algorithm, KID
from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from typing import Union
import pkcs11
from pkcs11.constants import ObjectClass
from pkcs11 import Attribute 



from pymdoccbor.exceptions import (
    MsoPrivateKeyRequired
)
from pymdoccbor import settings
from pymdoccbor.x509 import MsoX509Fabric
from pymdoccbor.tools import shuffle_dict
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from cbor_diag import *




class MsoIssuer(MsoX509Fabric):
    """

    """

    def __init__(
        self,
        data: dict,
        cert_path: str = None,
        key_label : str = None,
        user_pin : str = None,
        lib_path : str = None,
        slot_id : int = None,
        kid: str = None,
        alg: str = None,
        hsm : bool = False,
        private_key: Union[dict, CoseKey] = None,
        digest_alg: str = settings.PYMDOC_HASHALG
    ):

        if not hsm:
            if private_key and isinstance(private_key, dict):
                self.private_key = CoseKey.from_dict(private_key)
                if not self.private_key.kid:
                    self.private_key.kid = str(uuid.uuid4())
            elif private_key and isinstance(private_key, CoseKey):
                self.private_key = private_key
            else:
                raise MsoPrivateKeyRequired(
                    "MSO Writer requires a valid private key"
                )

            self.public_key = EC2Key(
                crv=self.private_key.crv,
                x=self.private_key.x,
                y=self.private_key.y
            )
        else:
            lib = pkcs11.lib(lib_path)
            token = lib.get_slots()[slot_id].get_token()

                # Open a session on our token
            
            with token.open(user_pin=user_pin) as session:

                try:
                    # Find the key in the HSM
                    #key_label = "brainppol2".encode("utf-8")
                    hsm_certs = session.get_objects({
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.LABEL: key_label,
                    })

                    hsm_certificate = next(hsm_certs)
                except pkcs11.exceptions.SessionHandleInvalid as e:
                    print(e)
                    print(type(e).__name__)


                #print("\n Certificate: ", hsm_certificate, "\n")

                # Retrieve the CKA_VALUE attribute (certificate value)
                cka_value = hsm_certificate[Attribute.VALUE]

            cert = x509.load_der_x509_certificate(cka_value, default_backend())
            public_key = cert.public_key()

            #print("\nPublic Key: ", public_key)

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Load the DER-encoded public key
            ec_public_key = serialization.load_der_public_key(public_key_bytes)

            public_numbers = ec_public_key.public_numbers()

            # Get the elliptic curve key parameters
            curve = public_numbers.curve

            #print(curve)

            curve_map = {
                "secp256r1": 1,     # NIST P-256
                "secp384r1": 2,     # NIST P-384
                "secp521r1": 3,     # NIST P-521
                "brainpoolP256r1": 8,   # Brainpool P-256
                "brainpoolP384r1": 9,   # Brainpool P-384
                "brainpoolP512r1": 10,  # Brainpool P-512
                # Add more curve mappings as needed
            }

            curve_identifier = curve_map.get(curve.name)
            
            # Extract the x and y coordinates from the public key
            x = public_numbers.x.to_bytes(
                (public_numbers.x.bit_length() + 7) // 8,  # Number of bytes needed
                'big'  # Byte order
            )

            y = public_numbers.y.to_bytes(
                (public_numbers.y.bit_length() + 7) // 8,  # Number of bytes needed
                'big'  # Byte order
            )

            self.public_key= EC2Key(
                crv=curve_identifier,
                x=x,
                y=y
            )

            self.public_key2 = {
                1: 2,
                -1: curve_identifier,
                -2: cbor2.dumps(x),
                -3: cbor2.dumps(y)
            }

            #print("Public key: ", cbor2diag(self.public_key.encode()))


        self.data: dict = data
        self.hash_map: dict = {}
        self.cert_path=cert_path
        self.disclosure_map: dict = {}
        self.digest_alg: str = digest_alg
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.hsm = hsm
        self.alg = alg
        self.kid = kid

        hashfunc = getattr(
            hashlib,
            settings.HASHALG_MAP[settings.PYMDOC_HASHALG]
        )

        digest_cnt = 0
        for ns, values in data.items():
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}
            for k, v in shuffle_dict(values).items():

                _rnd_salt = secrets.token_bytes(settings.DIGEST_SALT_LENGTH)


                if k == "birth_date":
                    tag = 1004
                    v = cbor2.CBORTag(1004,value=v)
                else:
                    tag = 24

                self.disclosure_map[ns][digest_cnt] = {
                    'digestID': digest_cnt,
                    'random': _rnd_salt,
                    'elementIdentifier': k,
                    'elementValue': v
                }

                self.hash_map[ns][digest_cnt] = hashfunc(
                    cbor2.dumps(
                        cbor2.CBORTag(
                            24,
                            value=cbor2.dumps(
                                self.disclosure_map[ns][digest_cnt]
                            )
                        )
                    )
                ).digest()

                digest_cnt += 1

    def format_datetime_repr(self, dt: datetime.datetime):
        return dt.isoformat().split('.')[0] + 'Z'

    def sign(
        self,
        device_key: Union[dict, None] = None,
        valid_from: Union[None, datetime.datetime] = None,
        doctype: str = None
    ) -> Sign1Message:
        """
            sign a mso and returns itprivate_key
        """
        utcnow = datetime.datetime.utcnow()
        if settings.PYMDOC_EXP_DELTA_HOURS:
            exp = utcnow + datetime.timedelta(
                hours=settings.PYMDOC_EXP_DELTA_HOURS
            )
        else:
            # five years
            exp = utcnow + datetime.timedelta(hours=(24 * 365) * 5)

        
            alg_map = {
                "ES256":"SHA-256",
                "ES384":"SHA-384",
                "ES512":"SHA-512"
            }
        
        payload = {
            'docType': doctype or list(self.hash_map)[0],
            'version': '1.0',
            'validityInfo': {
                'signed': cbor2.CBORTag(0, self.format_datetime_repr(utcnow)),
                'validFrom': cbor2.CBORTag(0, self.format_datetime_repr(valid_from or utcnow)),
                'validUntil': cbor2.CBORTag(0, self.format_datetime_repr(exp))
            },
            'valueDigests': self.hash_map,
            'deviceKeyInfo': {
                'deviceKey': self.public_key2,

            },
            'digestAlgorithm': alg_map.get(self.alg),
        }

        if(self.cert_path):
        
            # Load the DER certificate file
            with open(self.cert_path, "rb") as file:
                certificate = file.read()
            
            cert = x509.load_der_x509_certificate(certificate)

            _cert = cert.public_bytes(getattr(serialization.Encoding, "DER"))
        else:

            _cert = self.selfsigned_x509cert()


        if self.hsm:
            #print("payload diganostic notation: \n", cbor2diag(cbor2.dumps(cbor2.CBORTag(24,cbor2.dumps(payload)))))

            
            mso = Sign1Message(
                phdr={
                    Algorithm: self.alg,
                    #33: _cert
                },
                # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
                # 33 means x509chain standing to rfc9360
                # in both protected and unprotected for interop purpose .. for now.
                uhdr={33: _cert},
                payload=cbor2.dumps(cbor2.CBORTag(24,cbor2.dumps(payload))),
            )


        else:

            mso = Sign1Message(
                phdr={
                    Algorithm: self.private_key.alg,
                    #KID: self.private_key.kid,
                    #33: _cert
                },
                # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
                # 33 means x509chain standing to rfc9360
                # in both protected and unprotected for interop purpose .. for now.
                uhdr={33: _cert},
                payload=cbor2.dumps(cbor2.CBORTag(24,cbor2.dumps(payload)))
            )

            mso.key = self.private_key
        return mso
