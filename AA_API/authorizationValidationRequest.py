"""
Authorization Validation Request sent by AA to EA after ITS -> AA

"""

from models import (
    AuthorizationValidationRequest, 
    EtsiTs102941Data, 
    EtsiTs103097Data_Signed, 
    EtsiTs103097Data_Encrypted)
from ECDSA import (signECDSAsecp256r1)
from ECIES import (encrypt_ecies)
from AESCCM import (encrypt_AESCCM)
from functions import (json_custom, sha3_256Hash)
import pickle
import json

def make_AVRequest(ecSignature, sharedATRequest, privKeyAA, EA_Certificate):
    # Pasul 1 Se formeaza un obiect de tipul AuthorizationValidationRequest
    
    authorizationValidationRequest = AuthorizationValidationRequest(ecSignature, sharedATRequest)

    # Pasul 2 Se formeaza un obiect de tipul EtsiTs102941Data

    version = '1'
    content = authorizationValidationRequest
    etsiTs102941Data = EtsiTs102941Data(version, content)

    # Pasul 3 Se formeaza un obiect de tipul EtsiTs103097Data_Signed

    hashId = 'SHA256'
    tbsData = {'payload': etsiTs102941Data, 'headerInfo': ''}
    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)
    signature = signECDSAsecp256r1(json_tbsData_bytes, privKeyAA)
    signer = 'self'

    etsiTs103097Data_Signed = EtsiTs103097Data_Signed(hashId, tbsData, signer, signature)

    # Pasul 4 Se formeaza un obiect de tipul EtsiTs103097Data_Encrypted

    EA_Certificate_bytes = pickle.dumps(EA_Certificate)
    json_EA_Certificate_bytes = json_custom(EA_Certificate_bytes)

    recipientId = sha3_256Hash(json_EA_Certificate_bytes)
    recipientId_json = json.dumps(recipientId)
    recipientId = recipientId_json[:8]

    EA_pubKey = EA_Certificate.toBeSigned['verifyKeyIndicator']['verificationKey']

    etsiTs103097Data_Signed_bytes = pickle.dumps(etsiTs103097Data_Signed)

    # 4.1 Criptam etsiTs103097Data_Signed_bytes cu AES_CCM

    dataAESCCM = encrypt_AESCCM(etsiTs103097Data_Signed_bytes)

    AES_Key = dataAESCCM['AES-Key']

    del dataAESCCM['AES-Key']

    ciphertext = dataAESCCM

    # 4.2 Criptam cheia AESKEY folosita la 4.1 cu ECIES si o punem in encKey din recipients

    (V, c, t, salt) = encrypt_ecies(AES_Key, EA_pubKey)

    encKey = (V, c, t.digest(), salt)

    recipients = {'recipientId': recipientId, 'encKey': encKey}

    etsiTs103097Data_Encrypted = EtsiTs103097Data_Encrypted(recipients, ciphertext)

    return etsiTs103097Data_Encrypted, AES_Key