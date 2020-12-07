"""
Authorization Response sent by AA to ITS 

"""
from models import (AuthorizationResponse, ExplicitCertificate, EtsiTs102941Data, EtsiTs103097Data_Signed, EtsiTs103097Data_Encrypted)
from functions import (json_custom, sha3_256Hash)
from ECDSA import signECDSAsecp256r1
from AESCCM import (encrypt_AESCCM_withKey)
import pickle
import json

def make_authorizationResponse(aaId, itsRequest, V_enc, AA_privKey, aesKey):

    # Pasul 1 Se creeaza un obiect de tipul ExplicitCertificate
    _type = 'explicit'
    toBeSigned = {'verifyKeyIndicator': {
        'verificationKey': V_enc
    }}
    toBeSigned_bytes = pickle.dumps(toBeSigned)
    json_toBeSigned_bytes = json_custom(toBeSigned_bytes)

    signature = signECDSAsecp256r1(json_toBeSigned_bytes, AA_privKey)

    its_certificate_AT = ExplicitCertificate(_type, toBeSigned, signature)
    
    # Pasul 2 Se creeaza un obiect de tipul AuthorizationResponse
   
    # Pasul 2.1 Se formeaza hash-ul de itsRequest 
    hashITSReq = sha3_256Hash(itsRequest)
    hashITSReq_json = json.dumps(hashITSReq)
    hashITSReq = hashITSReq_json[:16]
    
    # Pasul 2.2 ResponseCode-ul este 0 pentru succes

    responseCode = '0'

    authorizationResponse = AuthorizationResponse(hashITSReq, responseCode, its_certificate_AT)
    
    # Pasul 3 Se creeaza un obiect de tipul EtsiTs102941Data

    version = '1'
    content = authorizationResponse

    etsiTs102941Data = EtsiTs102941Data(version, content)

    # Pasul 4 Se creeaza un obiect de tipul EtsiTs103097Data_Signed

    hashId = 'SHA256'
    tbsData = {'payload': etsiTs102941Data, 'headerInfo': ''}
    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)
    signature = signECDSAsecp256r1(json_tbsData_bytes, AA_privKey)
    signer = aaId

    etsiTs103097Data_Signed = EtsiTs103097Data_Signed(hashId, tbsData, signer, signature)


    # Pasul 5 Se creeaza un obiect de tipul EtsiTs103097Data_Encrypted

    etsiTs103097Data_Signed_bytes = pickle.dumps(etsiTs103097Data_Signed)

    dataAESCCM = encrypt_AESCCM_withKey(etsiTs103097Data_Signed_bytes, aesKey)

    del dataAESCCM['AES-Key']

    ciphertext = dataAESCCM

    # 5.1 In recipients se va pune hashId8 de cheia AES

    json_aesKey = json_custom(aesKey)

    hashAeskey = sha3_256Hash(json_aesKey)

    hashAeskey_json = json.dumps(hashAeskey)

    hashAesKeyId = hashAeskey_json[:8]

    recipients = {'symmetricEncryptionKey': hashAesKeyId}

    etsiTs103097Data_Encrypted = EtsiTs103097Data_Encrypted(recipients, ciphertext)

    return etsiTs103097Data_Encrypted