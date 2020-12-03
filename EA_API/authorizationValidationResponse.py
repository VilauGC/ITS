from models import (AuthorizationValidationResponse, 
EtsiTs102941Data, 
EtsiTs103097Data_Signed,
EtsiTs103097Data_Encrypted)
from functions import json_custom, sha3_256Hash
from ECDSA import signECDSAsecp256r1
from AESCCM import encrypt_AESCCM_withKey
import pickle
import json


def make_AVResponse(eaId,privKeyEA, aesKey, AVRequest):
    # Pasul 1 Se formeaza un obiect de tipul AuthorizationValidationResponse

    # 1.1 TODO Se creaza un hash din AVRequest-ul primit de EA de la AA si se pastreaza 16 bytes

    hashAVReq = sha3_256Hash(AVRequest)
    hashAVReq_json = json.dumps(hashAVReq)
    hashAVReq = hashAVReq_json[:16]

    # 1.2 ResponseCode-ul este 0 pentru succes

    responseCode = '0'

    # 1.3 TODO ConfirmedSubjectAttributes 

    confirmedSubjectAttributes = ''

    authorizationValidationResponse = AuthorizationValidationResponse(hashAVReq, responseCode, confirmedSubjectAttributes)

    # Pasul 2 Se formeaza un obiect de tipul EtsiTS102941Data

    version = '1'
    content = authorizationValidationResponse
    etsiTs102941Data = EtsiTs102941Data(version, content)

    # Pasul 3 Se formeaza un obiect de tipul EtsiTs103097Data_Signed

    hashId = 'SHA256'
    tbsData = {'payload': etsiTs102941Data, 'headerInfo': ''}
    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)
    signature = signECDSAsecp256r1(json_tbsData_bytes, privKeyEA)
    signer = eaId

    etsiTs103097Data_Signed = EtsiTs103097Data_Signed(hashId, tbsData, signer, signature)

    # Pasul 4 Se formeaza un obiect de tipul EtsiTs103097Data_Encrypted

    etsiTs103097Data_Signed_bytes = pickle.dumps(etsiTs103097Data_Signed)

    dataAESCCM = encrypt_AESCCM_withKey(etsiTs103097Data_Signed_bytes, aesKey)

    del dataAESCCM['AES-Key']

    ciphertext = dataAESCCM

    # 4.1 in recipients se va pune hashId8 de cheia AES
    json_aesKey = json_custom(aesKey)

    hashAeskey = sha3_256Hash(json_aesKey)

    hashAeskey_json = json.dumps(hashAeskey)

    hashAesKeyId = hashAeskey_json[:8]

    recipients = {'symmetricEncryptionKey': hashAesKeyId}

    etsiTs103097Data_Encrypted = EtsiTs103097Data_Encrypted(recipients, ciphertext)

    return etsiTs103097Data_Encrypted