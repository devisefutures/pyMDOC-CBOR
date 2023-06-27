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




class MsoIssuer(MsoX509Fabric):
    """

    """

    def __init__(
        self,
        data: dict,
        cert_path: str,
        key_label : str,
        user_pin : str,
        lib_path : str,
        slot_id : int,
        kid: str,
        alg: str,
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
                
                # Find the key in the HSM
                #key_label = "brainppol2".encode("utf-8")
                certificates = session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.LABEL: key_label,
                })[0]

                print("\n Certificate: ", certificates[0], "\n")

                cert = x509.load_der_x509_certificate(certificates[0].to_dict()['CKA_VALUE'], default_backend())
                public_key = cert.public_key()

                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                                # Load the DER-encoded public key
                ec_public_key = serialization.load_der_public_key(public_key_bytes)

                # Get the elliptic curve key parameters
                ec_params = ec_public_key.public_key().public_numbers().curve
                
                # Extract the x and y coordinates from the public key
                x = ec_public_key.public_key().public_numbers().x
                y = ec_public_key.public_key().public_numbers().y

                self.public_key= EC2Key(
                    crv=ec_params,
                    x=x,
                    y=y
                )


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

        payload = {
            'version': '1.0',
            'digestAlgorithm': settings.HASHALG_MAP[settings.PYMDOC_HASHALG],
            'valueDigests': self.hash_map,
            'deviceKeyInfo': {
                'deviceKey': device_key
            },
            'docType': doctype or list(self.hash_map)[0],
            'validityInfo': {
                'signed': cbor2.dumps(cbor2.CBORTag(0, self.format_datetime_repr(utcnow))),
                'validFrom': cbor2.dumps(cbor2.CBORTag(0, self.format_datetime_repr(valid_from or utcnow))),
                'validUntil': cbor2.dumps(cbor2.CBORTag(0, self.format_datetime_repr(exp)))
            }
        }

        if(self.cert_path):
        
            # Load the DER certificate file
            with open(self.cert_path, "rb") as file:
                certificate = file.read()
            
            cert = x509.load_der_x509_certificate(certificate)

            _cert = cert.public_bytes(getattr(serialization.Encoding, "DER"))
        else:

            _cert = self.selfsigned_x509cert()

        if not self.hsm:
            mso = Sign1Message(
                phdr={
                    Algorithm: self.alg,
                    KID: self.kid,
                    33: _cert
                },
                # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
                # 33 means x509chain standing to rfc9360
                # in both protected and unprotected for interop purpose .. for now.
                uhdr={33: _cert},
                payload=cbor2.dumps(payload)
            )

        else:

            mso = Sign1Message(
                phdr={
                    Algorithm: self.private_key.alg,
                    KID: self.private_key.kid,
                    33: _cert
                },
                # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
                # 33 means x509chain standing to rfc9360
                # in both protected and unprotected for interop purpose .. for now.
                uhdr={33: _cert},
                payload=cbor2.dumps(payload)
            )

            mso.key = self.private_key


        return mso
