"""
Used to decrypt the authorizationResponse from AA 
and extract the AT(authorization ticket -> certificate)
"""
from functions import (json_custom, json_to_bytes, sha3_256Hash)
from AESCCM import decrypt_AESCCM
from ECDSA import verifyECDSAsecp256r1
import pickle
import json

def decrypt_authorizationResponse(authorizationResponse, aesKey):
    
    # Pasul 1 Extrag obiectul etsiTs103097Data_Encrypted

    etsiTs103097Data_Encrypted_bytes = json_to_bytes(authorizationResponse)
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
        "C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\AA_Certificate.txt", 'rb')
        AA_Certificate_bytes = f.read()
        AA_Certificate = pickle.loads(AA_Certificate_bytes)
        f.close()

        AA_pubKey = AA_Certificate.toBeSigned['verifyKeyIndicator']['verificationKey']

        tbsData = etsiTs103097Data_Signed.tbsData
        tbsData_bytes = pickle.dumps(tbsData)
        json_tbsData_bytes = json_custom(tbsData_bytes)
        signature_to_verify = etsiTs103097Data_Signed.signature
        validSignature = verifyECDSAsecp256r1(json_tbsData_bytes, signature_to_verify, (AA_pubKey.x, AA_pubKey.y))

        if(validSignature):
            # Pasul 5 Se extrage obiectul de tipul etsiTs102941Data
            etsiTs102941Data = tbsData['payload']
            
            # Pasul 6 Se extrage obiectul de tipul authorizationResponse

            authorizationResponse = etsiTs102941Data.content

            # Pasul 7 Se extrage certificatul din authorizationResponse

            authorizationTicket = authorizationResponse.certificate

            return authorizationTicket
        else: 
            return 'Something went wrong with signature checking in decrypt_authorizationResponse'
    else:
        return 'This is not the right AES key'





    
    
    
    
    
    
    
    
