from enum import Enum


class IEEE1609dot2Data:
    """
    A class used to represent an IEEE1609dot2Data

    Paramenters
    -----------
    protocolVersion: Uint8(3), default 3
    content: Ieee1609Dot2Content

    """

    def __init__(self, content, protocolVersion=3):
        self.protocolVersion = protocolVersion
        self.content = content


class SignedDataPayload:
    """
    A class used to represent a Signed Data Payload

        Parameters
        ----------
        data: Ieee1609Dot2Data, optional
        extDataHash: HashedData, optional

        Observation
        -----------
        At least one of the params is present
        It's not allowed to have both of the params  

    """

    def __init__(self, data=None, extDataHash=None):
        self.data = data
        self.extDataHash = extDataHash


class Ieee1609Dot2Content:
    """
    A class used to represent an Ieee1609Dot2Content

        Parameters
        ----------
        unsecuredData: Opaque, optional
        signedData: SignedData, optional
        encryptedData: EncryptedData, optional
        signedCertificatRequest: Opaque

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, unsecuredData=None, signedData=None, encryptedData=None, signedCertificateRequest=None):
        self.unsecuredData = unsecuredData
        self.signedData = signedData
        self.encryptedData = encryptedData
        self.signedCertificateRequest = signedCertificateRequest


class SignedData:
    """
    A class used to represent a SignedData

        Parameters
        ----------
        hashId: HashAlgorithm
        tbsData: ToBeSignedData
        signer: SignerIdentifier
        signature: Signature

    """

    def __init__(self, hashId, tbsData, signer, signature):
        self.hashId = hashId
        self.tbsData = tbsData
        self.signer = signer
        self.signature = signature


class SignerIdentifier:
    """
    A class used to represent a SignerIdentifier

        Parameters
        ----------
        digest: HashedId8, Optional
        certificate: SequenceOfCertificate, Optional
        selfArg: NULL, Optional

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, digest=None, certificate=None, selfArg=None):
        self.digest = digest
        self.certificate = certificate
        self.selfArg = selfArg


class ToBeSignedData:
    """
    A class used to represent a ToBeSignedData

        Parameters
        ----------
        payload: SignedDataPayload
        headerInfo: HeaderInfo

    """

    def __init__(self, payload, headerInfo):
        self.payload = payload
        self.headerInfo = headerInfo


class HashedData:
    """
    A class used to represent a HashedData

        Parameters
        ----------
        sha256HashedData: Octet String (Size(32))

    """

    def __init__(self, sha256HashedData):
        self.sha256HashedData = sha256HashedData


class HeaderInfo:
    """
    A class used to represent a HeaderInfo

        Parameters
        ----------
        psid: Psid
        generationTime: Time64, Optional
        expiryTime: Time64, Optional
        generationLocation: ThreeDLocation, Optional
        p2pcdLearningRequest: HashedId3, Optional
        missingCrlIdentifier: MissingCrlIdentifier, Optional
        encryptionKey: EncryptionKey, Optional
        inlineP2pcdRequest: SequenceOfHashedId3, Optional
        requestedCertificate: Certificate, Optional


    """

    def __init__(self, psid, generationTime=None, expiryTime=None, generationLocation=None,
                 p2pcdLearningRequest=None,
                 missingCrlIdentifier=None,
                 encryptionKey=None,
                 inlineP2pcdRequest=None,
                 requestedCertificate=None):
        self.psid = psid
        self.generationTime = generationTime
        self.expiryTime = expiryTime
        self.generationLocation = generationLocation
        self.p2pcdLearningRequest = p2pcdLearningRequest
        self.missingCrlIdentifier = missingCrlIdentifier
        self.encryptionKey = encryptionKey
        self.inlineP2pcdRequest = inlineP2pcdRequest
        self.requestedCertificate = requestedCertificate


class MissingCrlIdentifier:
    """
    A class used to represent a MissingCrlIdentifier

        Parameters
        ----------
        cracaId: HashedId3


    """

    def __init__(self, cracaId, crlSeries):
        self.cracaId = cracaId
        self.crlSeries = crlSeries


class Countersignature(IEEE1609dot2Data):
    """
    A class used to represent a CounterSignature: IEEE1609dot2Data

    Parameters
    ----------
    content: Ieee1609Dot2Content

    Observation
    -----------
    content {
        signedData {
            tbsData{
                payload{
                    data, ABSENT
                    extDataHash, PRESENT
                }
                headerInfo{
                    generationTime, PRESENT
                    expiryTime, ABSENT
                    generationLocation, ABSENT
                    p2pcdLearningRequest, ABSENT
                    missingCrlIdentifier, ABSENT
                    encryptionKey, ABSENT
                }
            }
        }
    }

    """

    def __init__(self, content):
        self.content = content

################################################
### Structures for describing encrypted data ###
################################################


class EncryptedData:
    """
    A class used to represent an EncryptedData

        Parameters
        ----------
        recipients: SequenceOfRecipientInfo
        ciphertext: SymmetricCiphertext

    """

    def __init__(self, recipients, ciphertext):
        self.recipients = recipients
        self.ciphertext = ciphertext


class RecipientInfo:
    """
    A class used to represent a RecipientInfo

        Parameters
        ----------
        pskRecipInfo: PreSharedKeyRecipientInfo, Optional
        symmRecipInfo: SymmRecipientInfo, Optional
        certRecipInfo: PKRecipientInfo, Optional
        signedDataRecipInfo: PKRecipientInfo, Optional
        rekRecipInfo: PKRecipientInfo, Optional

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, pskRecipInfo=None, symmRecipInfo=None, certRecipInfo=None, signedDataRecipInfo=None, rekRecipInfo=None):
        self.pskRecipInfo = pskRecipInfo
        self.symmRecipInfo = symmRecipInfo
        self.certRecipInfo = certRecipInfo
        self.signedDataRecipInfo = signedDataRecipInfo
        self.rekRecipInfo = rekRecipInfo


class SequenceOfRecipientInfo:
    """
    A class used to represent a SEQUENCE of RecipientInfo

    """
    pass


class PreSharedKeyRecipientInfo:
    """
    A class used to represent a PreSharedKeyRecipientInfo: HashedId8

    """
    pass


class SymmRecipientInfo:
    """
    A class used to represent a SymmRecipientInfo

        Parameters
        ----------
        recipientId: HashedId8
        encKey: SymmetricCiphertext

    """

    def __init__(self, recipientId, encKey):
        self.recipientId = recipientId
        self.encKey = encKey


class PKRecipientInfo:
    """
    A class used to represent a PKRecipientInfo

        Parameters
        ----------
        recipientId: HashedId8
        encKey: EncryptedDataEncryptionKey

    """

    def __init__(self, recipientId, encKey):
        self.recipientId = recipientId
        self.encKey = encKey


class EncryptionDataEncryptionKey:
    """
    A class used to represent an EncryptionDataEncryptionKey

        Parameters
        ----------
        eciesNist256: EciesP256EncryptedKey, Optional
        eciesBrainPoolP256rl: EciesP256EncryptedKey, Optional

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, eciesNist256=None, eciesBrainpoolP256r1=None):
        self.eciesNist256 = eciesNist256
        self.eciesBrainpoolP256r1 = eciesBrainpoolP256r1


class SymmetricCiphertext:
    """
    A class used to represent a SymmetricCiphertext

        Parameters
        ----------
        aes128ccm: AesCcmCiphertext, Optional
        ...

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, aes128ccm=None):
        self.aes128ccm = aes128ccm


class AesCcmCiphertext:
    """
    A class used to represent an AesCcmCiphertext

        Parameters
        ----------
        nonce: Octet String (SIZE(12))
        ccmCiphertext: Opaque (16 bytes longer than plaintext)

    """

    def __init__(self, nonce, ccmCiphertext):
        self.nonce = nonce
        self.ccmCiphertext = ccmCiphertext

################################
# Certificates and other security management data structures
################################


class CertificateBase:
    """
    A class used to represent a CertificateBase

        Parameters
        ----------
        version: Uint8(3)
        typeArg: CertificateType
        issuer: IssuerIdentifier
        toBeSigned: ToBeSignedCertificate
        signature: Signature, Optional

    """

    def __init__(self, version, typeArg, issuer, toBeSigned, signature=None):
        self.version = version
        self.typeArg = typeArg
        self.issuer = issuer
        self.toBeSigned = toBeSigned
        self.signature = signature


class Certificate(CertificateBase):
    """
    A class used to represent a Certificate
    Can be of type ImplicitCertificat or ExplicitCertificate

    """
    pass


class SequenceOfCertificate:
    """
    A class used to represent a SequenceOfCertificate

    """
    pass


class CertificateType(Enum):
    explicit = 0
    implicit = 1


class ImplicitCertificate(CertificateBase):
    """
    A class used to represent an ImplicitCertificate: CertificateBase

        Parameters
        ----------
        toBeSigned: ToBeSignedCertificate
        typeArg: CertificateType, DEFAULT "implicit"

        Observation
        -----------
        toBeSigned{
            verifyKeyIndicator{
                reconstructionValue is PRESENT
            }
        }
        signature is ABSENT
    """

    def __init__(self, toBeSigned, typeArg='implicit'):
        self.toBeSigned = toBeSigned
        self.typeArg = typeArg


class ExplicitCertificate(CertificateBase):
    """
    A class used to represent an ExplicitCertificate: CertificateBase

        Parameters
        ----------
        toBeSigned: ToBeSignedCertificate
        typeArg: CertificateType, DEFAULT "explicit"
        signature: Signature

        Observation
        -----------
        toBeSigned{
            verifyKeyIndicator{
                verificationKey is PRESENT
            }
        }
        signature PRESENT

    """

    def __init__(self, toBeSigned, signature, typeArg='explicit'):
        self.toBeSigned = toBeSigned
        self.signature = signature
        self.typeArg = typeArg


class IssuerIdentifier:
    """
    A class used to represent an IssuerIdentifier

        Parameters
        ----------
        sha256AndDigest: HashedId8, Optional
        selfArg: HashAlgorithm, Optional
        sha384AndDigest: HashedId8, Optional

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, sha256AndDigest=None, selfArg=None, sha384AndDigest=None):
        self.sha256AndDigest = sha256AndDigest
        self.selfArg = selfArg
        self.sha384AndDigest = sha384AndDigest


class ToBeSignedCertificate:
    """
    A class used to represent a ToBeSignedCertificate

        Parameters
        ----------
        idArg: CertificateId
        cracaId: HashedId3
        crlSeries: CrlSeries
        validityPeriod: ValidityPeriod
        region: GeographicRegion, Optional
        assuranceLevel: SubjectAssurance, Optional
        appPermissions: SequenceOfPsidSsp, Optional
        certIssuePermissions: SequenceOfPsidGroupPermissions, Optional
        certRequestPermissions: SequenceOfPsidGroupPermissions, Optional
        canRequestRollover: NULL, Optional
        encryptionKey: PublicEncryptionKey, Optional
        verifyKeyIndicator: VerificationKeyIndicator, Optional

        Observation
        -----------
        At least one of the following params has to be Present: 
            appPermissions, certIssuePermissions, certRequestPermissions.

    """

    def __init__(self,
                 idArg,
                 cracaId,
                 crlSeries,
                 validityPeriod,
                 region=None,
                 assuranceLevel=None,
                 appPermissions=None,
                 certRequestPermission=None,
                 canRequestRollover=None,
                 encryptionKey=None,
                 verifyKeyIndicator=None):
        self.idArg = idArg
        self.cracaId = cracaId
        self.crlSeries = crlSeries
        self.validityPeriod = validityPeriod
        self.region = region
        self.assuranceLevel = assuranceLevel
        self.appPermissions = appPermissions
        self.certRequestPermission = certRequestPermission
        self.canRequestRollover = canRequestRollover
        self.encryptionKey = encryptionKey
        self.verifyKeyIndicator = verifyKeyIndicator


class CertificateId:
    """
    A class used to represent a CertificateId

        Parameters
        ----------
        linkageData: LinkageData, Optional
        name: Hostname, Optional
        binaryId: Octet String(SIZE(1..64)), Optional
        none: NULL, Optional

    """

    def __init__(self, linkageData=None, name=None, binaryId=None, none=None):
        self.linkageData = linkageData
        self.name = name
        self.binaryId = binaryId
        self.none = none


class LinkageData:
    """
    A class used to represent a LinkageData

        Parameters
        ----------
        iCert: IValue
        linkage_value: LinkageValue
        group_linkage_value: GroupLinkageValue, Optional

    """

    def __init__(self, iCert, linkage_value, group_linkage_value=None):
        self.iCert = iCert
        self.linkage_value = linkage_value
        self.group_linkage_value = group_linkage_value


class PsidGroupPermissions:
    """
    A class used to represent a PsidGroupPermissions

        Parameters
        ----------
        subjectPermissions: SubjectPermissions
        minChainLength: INTEGER, DEFAULT 1
        chainLengthRange: INTEGER, DEFAULT 0
        eeType: EndEntityType, DEFAULT {app}

    """

    def __init__(self, subjectPertmissions, minChainLength=1, chainLengthRange=0, eeType=0):
        self.subjectPertmissions = subjectPertmissions
        self.minChainLength = minChainLength
        self.chainLengthRange = chainLengthRange
        self.eeType = eeType


class SubjectPermissions:
    """
    A class used to represent a SubjectPermissions

        Parameters
        ----------
        explicit: SequenceOfPsidSspRange, Optional
        all: NULL, Optional

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, explicit=None, allArg=None):
        self.explicit = explicit
        self.allArg = allArg


class VerificationKeyIndicator:
    """
    A class used to represent a VerificationKeyIndicator

        Parameters
        ----------
        verificationKey: PublicVerificationKey, Optional
        reconstructionValue: EccP256CurvePoint, Optional

        Observation
        -----------
        Only one param can be present

    """

    def __init__(self, verificationKey=None, reconstructionValue=None):
        self.verificationKey = verificationKey
        self.reconstructionValue = reconstructionValue
