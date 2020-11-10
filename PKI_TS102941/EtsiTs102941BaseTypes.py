from SEC_TS103097.EtsiTs103097Module import EtsiTs103097Data_Encrypted

class CertificateFormat:
    def __init__(self, ts103097v131=1):
        self.ts103097v131 = ts103097v131


class CertificateSubjectAttributes:
    def __init__(self, idArg=None, validityPeriod=None, region=None, assuranceLevel=None, appPermissions=None, certIssuePermissions=None):
        self.idArg = idArg
        self.validityPeriod = validityPeriod
        self.region = region
        self.assuranceLevel = assuranceLevel
        self.appPermissions = appPermissions
        self.certIssuePermissions = certIssuePermissions


class EcSignature:
    def __init__(self, encryptedEcSignature=None, ecSignature=None):
        self.encryptedEcSignature = encryptedEcSignature
        self.ecSignature = ecSignature


class PublicKeys:
    def __init__(self, verificationKey, encryptionKey=None):
        self.verificationKey = verificationKey
        self.encryptionKey = encryptionKey


class Version:
    def __init__(self, v1=1):
        self.v1 = v1

class EtsiTs103097Data_Encrypted_Unicast(EtsiTs103097Data_Encrypted):
    def __init__(self, content):
        self.content = content

class EtsiTs103097Data_SignedAndEncrypted_Unicast(EtsiTs103097Data_Encrypted_Unicast):
    pass


