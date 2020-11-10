from SEC_TS103097.EtsiTs103097Module import EtsiTs103097Data_Signed

# TODO 
# de importat din modulul EtsiTs102941BaseTypes

from EtsiTs102941BaseTypes import (EtsiTs103097Data_Encrypted_Unicast, EtsiTs103097Data_SignedAndEncrypted_Unicast)

class EnrolmentRequestMessage(EtsiTs103097Data_SignedAndEncrypted_Unicast):
    def __init__(self, content):
        self.content = content


class EnrolmentResponseMessage(EtsiTs103097Data_SignedAndEncrypted_Unicast):
    def __init__(self, content):
        self.content = content


class AuthorizationRequestMessage(EtsiTs103097Data_Encrypted_Unicast):
    def __init__(self, content):
        self.content = content


class AuthorizationRequestMessageWithPop(EtsiTs103097Data_SignedAndEncrypted_Unicast):
    def __init__(self, content):
        self.content = content


class AuthorizationResponseMessage(EtsiTs103097Data_SignedAndEncrypted_Unicast):
    def __init__(self, content):
        self.content = content


class CertificateRevocationListMessage(EtsiTs103097Data_Signed):
    def __init__(self, content):
        self.content = content


class TlmCertificateTrustListMessage(EtsiTs103097Data_Signed):
    def __init__(self, content):
        self.content = content


class RcaCertificateTrustListMessage(EtsiTs103097Data_Signed):
    def __init__(self, content):
        self.content = content


class AuthorizationValidationRequestMessage(EtsiTs103097Data_SignedAndEncrypted_Unicast):
    def __init__(self, content):
        self.content = content


class AuthorizationValidationResponseMessage(EtsiTs103097Data_SignedAndEncrypted_Unicast):
    def __init__(self, content):
        self.content = content


class CaCertificateRequestMessage(EtsiTs103097Data_Signed):
    def __init__(self, content):
        self.content = content


class CaCertificateRekeyingMessage(EtsiTs103097Data_Signed):
    def __init__(self, content):
        self.content = content    


class EtsiTs102941Data:
    def __init__(self, version, content):
        self.version = version
        self.content = content


class EtsiTs102941DataContent:
    def __init__(self, enrolmentRequest=None, enrolmentResponse=None, authorizationRequest=None, authorizationResponse=None, certificateRevocationList=None, certificateTrustListTlm=None, certificateTrustListRca=None, authorizationValidationRequest=None, authorizationValidationResponse=None, caCertificateRequest=None):
        self.enrolmentRequest = enrolmentRequest
        self.enrolmentResponse = enrolmentResponse
        self.authorizationRequest = authorizationRequest
        self.authorizationResponse = authorizationResponse
        self.certificateRevocationList = certificateRevocationList
        self.certificateTrustListTlm = certificateTrustListTlm
        self.certificateTrustListRca = certificateTrustListRca
        self.authorizationValidationRequest = authorizationValidationRequest
        self.authorizationValidationResponse = authorizationValidationResponse
        self.caCertificateRequest = caCertificateRequest
