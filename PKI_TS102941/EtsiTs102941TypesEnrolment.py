from enum import Enum
from SEC_TS103097.EtsiTs103097Module import EtsiTs103097Data_Signed

class EnrolmentResponseCode(Enum):
    ok = 0
    cantparse = 0
    badcontenttype = 0
    imnottherecipient = 0
    unknownencryptionalgorithm = 0
    decryptionfailed = 0
    unknownits = 0
    invalidsignature = 0
    invalidencryptionkey = 0
    baditsstatus = 0
    incompleterequest = 0
    deniedpermissions = 0
    invalidkeys = 0
    deniedrequest = 0


class InnerEcRequestSignedForPop(EtsiTs103097Data_Signed):
    pass


class InnerEcRequest:
    def __init__(self, itsId, certificateFormat, publicKeys, requestedSubjectAttributes):
        self.itsId = itsId
        self.certificateFormat = certificateFormat 
        self.publicKeys = publicKeys
        self.requestedSubjectAttributes = requestedSubjectAttributes


class InnerEcResponse:
    def __init__(self, requestedHash, responseCode, certificate = None):
        self.requestedHash = requestedHash
        self.responseCode = responseCode
        self.certificate = certificate