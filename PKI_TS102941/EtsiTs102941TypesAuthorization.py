from enum import Enum


class AuthorizationResponseCode(Enum):
    ok = 0
    its_aa_cantparse = 0
    its_aa_badcontenttype = 0
    its_aa_imnottherecipient = 0
    its_aa_unknownencryptionalgorithm = 0
    its_aa_decryptionfailed = 0
    its_aa_keysdontmatch = 0
    its_aa_incompleterequest = 0
    its_aa_invalidencryptionkey = 0
    its_aa_outofsyncrequest = 0
    its_aa_unknownea = 0
    its_aa_invalidea = 0
    its_aa_deniedpermissions = 0
    aa_ea_cantreachea = 0
    ea_aa_cantparse = 0
    ea_aa_badcontenttype = 0
    ea_aa_imnottherecipient = 0
    ea_aa_unknownencryptionalgorithm = 0
    ea_aa_decryptionfailed = 0
    invalidaa = 0
    invalidaasignature = 0
    wrongea = 0
    unknownits = 0
    invalidsignature = 0
    invalidencryptionkey = 0
    deniedpermissions = 0
    deniedtoomanycerts = 0


class InnerAtRequest:
    def __init__(self, publicKeys, hmacKey, sharedAtRequest, ecSignature):
        self.publicKeys = publicKeys
        self.hmacKey = hmacKey
        self.sharedAtRequest = sharedAtRequest
        self.ecSignature = ecSignature


class SharedAtRequest:
    def __init__(self, eaId, keyTag, certificateFormat, requestSubjectAttributes):
        self.eaId = eaId
        self.keyTag = keyTag
        self.certificateFormat = certificateFormat
        self.requestSubjectAttributes = requestSubjectAttributes


class InnerAtResponse:
    def __init__(self, requestHash, responseCode, certificate = None):
        self.requestHash = requestHash
        self.responseCode = responseCode 
        self.certificate = certificate



