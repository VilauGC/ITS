class InnerEcRequest:
    def __init__(self, itsId, certificateFormat, verificationKey, requestedSubjectAttributes):
        self.itsId = itsId
        self.certificateFormat = certificateFormat
        self.verificationKey = verificationKey
        self.requestedSubjectAttributes = requestedSubjectAttributes


class InnerEcResponse:
    def __init__(self, requestHash, responseCode, certificate):
        self.requestHash = requestHash
        self.responseCode = responseCode
        self.certificate = certificate


class EtsiTs103097Data_Signed:
    def __init__(self, hashId, tbsData, signer, signature):
        self.hashId = hashId
        self.tbsData = tbsData
        self.signer = signer
        self.signature = signature


class EtsiTs103097Data_Encrypted:
    def __init__(self, recipients, ciphertext):
        self.recipients = recipients
        self.ciphertext = ciphertext


class EtsiTs102941Data:
    def __init__(self, version, content):
        self.version = version
        self.content = content


class ExplicitCertificate:
    def __init__(self, _type, toBeSigned, signature):
        self.type = _type
        self.toBeSigned = toBeSigned
        self.signature = signature
