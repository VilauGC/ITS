from enum import Enum


class AuthorizationValidationResponseCode(Enum):
    ok = 0
    cantparse = 0
    badcontenttype = 0
    imnottherecipient = 0
    unknownencryptionalgorithm = 0
    decryptionfailed = 0
    invalidaa = 0
    invalidaasignature = 0
    wrongea = 0
    unknownits = 0
    invalidsignature = 0
    invalidencryptionkey = 0
    deniedpermissions = 0
    deniedtoomanycerts = 0
    deniedrequest = 0


class AuthorizationValidationRequest:
    def __init__(self, sharedAtRequest, ecSignature):
        self.sharedAtRequest = sharedAtRequest
        self.ecSignature = ecSignature


class AuthorizationValidationResponse:
    def __init__(self, requestHash, responseCode, confirmedSubjectAttributes):
        self.requestHash = requestHash
        self.responseCode = responseCode
        self.confirmedSubjectAttributes = confirmedSubjectAttributes


