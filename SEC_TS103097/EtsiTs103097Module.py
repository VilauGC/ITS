from SEC_TS103097.IEEE1609dot2 import (ExplicitCertificate,
                                       ToBeSignedCertificate,
                                       IEEE1609dot2Data, SignedDataPayload)
# Inceput de modul: EtsiTs103097Module.py


class EtsiTs103097Certificate(ExplicitCertificate):
    """
    A class used to represent an EtsiTs103097Certificate: ExplicitCertificate
        
        Observation
        -----------
        toBeSigned{
            id{
                linkageData, ABSENT
                binaryId, ABSENT
            }
            certRequestPermissions, ABSENT
            canRequestRollover, ABSENT
        }
    
    """
    # toBeSigned este de tipul ToBeSignedCertificate
    def __init__(self, toBeSigned):
        self.toBeSigned = toBeSigned


class SingleEtsiTs103097Certificate:
    """
    A class used to represent a SingleEtsiTs103097Certificate

        Parameters
        ----------
        only: EtsiTs103097Certificate
    
    """
    def __init__(self, only):
        self.only = only


class EtsiTs103097Data(IEEE1609dot2Data):
    """
    A class used to represent EtsiTs103097Data: IEEE1609dot2Data

        Parameters
        ----------
        content: Ieee1609Dot2Content
    
    """
    def __init__(self, content):
        self.content = content


class EtsiTs103097Data_Signed(EtsiTs103097Data):
    """
    A class used to represent EtsiTs103097Data_Signed: EtsiTs103097Data

        Parameters
        ----------
        content: Ieee1609Dot2Content

        Observation
        -----------
        content{
            signedData{
                tbsData{
                    payload{
                        data{
                            content{
                                unsecuredData containing ToBeSignedDataContent
                            }
                        }, PRESENT
                    }
                }
            }
        }
    
    """
    def __init__(self, content):
        self.content = content


class EtsiTs103097Data_SignedExternalPayload(EtsiTs103097Data):
    """
    A class used to represent EtsiTs103097Data_SignedExteralPayload: EtsiTs103097Data

        Parameters
        ----------
        content: Ieee1609Dot2Content

        Observation
        -----------
        content{
            signedData{
                tbsData{
                    payload{
                        extDataHash{
                            sha256HashedData, PRESENT
                        }
                    }
                }, PRESENT
            }
        }
    
    """
    def __init__(self, content):
        self.content = content


class EtsiTs103097Data_Encrypted(EtsiTs103097Data):
    """
    A class used to represent EtsiTs103097Data_Encrypted: EtsiTs103097Data

        Parameters
        ----------
        content: Ieee1609Dot2Content

        Observation
        -----------
        content{
            encryptedData{
                ciphertext{
                    aes128ccm{
                        ccmCiphertext --ccm encryption of ToBeEncryptedDataContent
                    }
                }
            }
        }
    
    """
    def __init__(self, content):
        self.content = content

class EtsiTs103097Data_SignedAndEncrypted(EtsiTs103097Data_Encrypted):
    """
    A class used to represent EtsiTs103097Data_SignedAndEncrypted: EtsiTs103097Data_Encrypted
    
    """
    pass

mesajToBeSigned = ToBeSignedCertificate()
etsiCertificate = EtsiTs103097Certificate(mesajToBeSigned)
signedDataPayload = SignedDataPayload()
