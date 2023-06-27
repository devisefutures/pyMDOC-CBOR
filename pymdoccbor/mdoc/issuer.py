import binascii
import cbor2
import logging

from pycose.keys import CoseKey
from typing import Union

from pymdoccbor.mso.issuer import MsoIssuer

logger = logging.getLogger('pymdoccbor')


class MdocCborIssuer:

    def __init__(self,key_label :str = None, user_pin :str = None, lib_path :str = None, slot_id :int = None, hsm : bool =False, alg: str = None, kid: str = None, private_key: Union[dict, CoseKey] = {}):
        self.version: str = '1.0'
        self.status: int = 0
        if private_key and isinstance(private_key, dict):
            self.private_key = CoseKey.from_dict(private_key)
        
        self.signed :dict = {}
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.hsm = hsm
        self.alg = alg
        self.kid = kid

    def new(
        self,
        data: dict,
        devicekeyinfo: Union[dict, CoseKey],
        doctype: str,
        cert_path: str = None
    ):
        """
        create a new mdoc with signed mso
        """
        if isinstance(devicekeyinfo, dict):
            devicekeyinfo = CoseKey.from_dict(devicekeyinfo)
        else:
            devicekeyinfo: CoseKey = devicekeyinfo

        if self.hsm:
            msoi = MsoIssuer(
                data=data,
                cert_path=cert_path,
                hsm=self.hsm,
                key_label=self.key_label,
                user_pin=self.user_pin,
                lib_path=self.lib_path,
                slot_id=self.slot_id,
                alg=self.alg,
                kid=self.kid
            )
            
        else:
            msoi = MsoIssuer(
                data=data,
                private_key=self.private_key,
                cert_path=cert_path
            )

        mso = msoi.sign()

        # TODO: for now just a single document, it would be trivial having
        # also multiple but for now I don't have use cases for this
        res = {
            'version': self.version,
            'documents': [
                {
                    'docType': doctype,  # 'org.iso.18013.5.1.mDL'
                    'issuerSigned': {
                        "nameSpaces": {
                            ns: [
                                cbor2.CBORTag(24, value={k: v}) for k, v in dgst.items()
                            ]
                            for ns, dgst in msoi.disclosure_map.items()
                        },
                        "issuerAuth": mso.encode(hsm=self.hsm,key_label=self.key_label, user_pin=self.user_pin, lib_path=self.lib_path,slot_id=self.slot_id)
                    },
                    'deviceSigned': {
                        # TODO
                    }
                }
            ],
            'status': self.status
        }
        
        self.signed = res
        return self.signed
    
    def dump(self):
        """
            returns bytes
        """
        return cbor2.dumps(self.signed)

    def dumps(self):
        """
            returns AF binary repr
        """
        return binascii.hexlify(cbor2.dumps(self.signed))
