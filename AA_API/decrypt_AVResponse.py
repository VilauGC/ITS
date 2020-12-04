"""
Decrypt the authorizationValidationResponse from EA

"""
from functions import (json_custom, json_to_bytes, sha3_256Hash)
from AESCCM import decrypt_AESCCM
from ECDSA import verifyECDSAsecp256r1
import pickle
import json


def decrypt_AVResponse(message, aesKey):
    # Pasul 1 Extrag obiectul etsiTs103097Data_Encrypted
    etsiTs103097Data_Encrypted_bytes = json_to_bytes(message)
    etsiTs103097Data_Encrypted = pickle.loads(etsiTs103097Data_Encrypted_bytes)
    # Pasul 2 Verific hash-ul cheii AES cu care a fost criptat
    json_aesKey = json_custom(aesKey)
    hashAeskey = sha3_256Hash(json_aesKey)
    hashAeskey_json = json.dumps(hashAeskey)
    hashAesKeyId = hashAeskey_json[:8]
    hashAesToVerify = etsiTs103097Data_Encrypted.recipients['symmetricEncryptionKey']
    if(hashAesKeyId == hashAesToVerify):
        #Pasul 3 Decriptez ciphertextul cu ajutorul alg aesccm cu cheia aesKey
        ciphertext = etsiTs103097Data_Encrypted.ciphertext
        cipher_to_decrypt = ciphertext['ciphertext']
        auth_tag = ciphertext['auth-tag']
        nonce = ciphertext['nonce']
        header = ciphertext['header']
        
        etsiTs103097Data_Signed_bytes = decrypt_AESCCM(aesKey, nonce, cipher_to_decrypt, auth_tag, header)

        etsiTs103097Data_Signed = pickle.loads(etsiTs103097Data_Signed_bytes)

        # Pasul 4 Se verifica signature peste tbsData din etsiTs103097Data_Signed
        f = open(
        "C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\EA_Certificate.txt", 'rb')
        EA_Certificate_bytes = f.read()
        EA_Certificate = pickle.loads(EA_Certificate_bytes)
        f.close()

        EA_pubKey = EA_Certificate.toBeSigned['verifyKeyIndicator']['verificationKey']

        tbsData = etsiTs103097Data_Signed.tbsData
        tbsData_bytes = pickle.dumps(tbsData)
        json_tbsData_bytes = json_custom(tbsData_bytes)
        signature_to_verify = etsiTs103097Data_Signed.signature
        validSignature = verifyECDSAsecp256r1(json_tbsData_bytes, signature_to_verify, (EA_pubKey.x, EA_pubKey.y))

        if(validSignature):
            # Pasul 5 Se extrage obiectul de tipul etsiTs102941Data
            etsiTs102941Data = tbsData['payload']

            # Pasul 6 Se extrage obiectul de tipul authorizationValidationResponse

            authorizationValidationResponse = etsiTs102941Data.content

            # Pasul 7 Se extrage responseCode-ul din authorizationVAlidationResponse

            responseCode = authorizationValidationResponse.responseCode

            return responseCode
        else:
            return 'Something went wrong with signature checking in decrypt_AVResponse'
    else:
        return 'This is not the right AES key'     



