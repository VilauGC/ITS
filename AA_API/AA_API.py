import sys
sys.path.append("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\UTILS")

from flask import Flask, request
from functions import (json_to_bytes, json_custom, generate_hmac)
from ECDSA import sha3_256Hash, verifyECDSAsecp256r1
from ECIES import decrypt_ecies
import pickle
import json

app = Flask(__name__)

@app.route('/its-authorization', methods=['POST'])
def its_authorization():
    # Pasul 1 Se extrage obiectul etsiTs103097Data_Encrypted din request data
 
    json_etsiTs103097Data_Encrypted = request.get_json()
    
    etsiTs103097Data_Encrypted_bytes = json_to_bytes(json_etsiTs103097Data_Encrypted)

    etsiTs103097Data_Encrypted = pickle.loads(etsiTs103097Data_Encrypted_bytes)

    recipients = etsiTs103097Data_Encrypted.recipients
    ciphertext = etsiTs103097Data_Encrypted.ciphertext

    # Pasul 2 Se citeste certificatul AA-ului pentru a verifica recipientId

    f = open(
        "C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\AA_Certificate.txt", 'rb')
    AA_Certificate_bytes = f.read()
    AA_Certificate = pickle.loads(AA_Certificate_bytes)
    f.close()
    
    # Pasul 2.1 Se creeaza un hash pentru certificatul AA-ului 
    # pentru a verifica recipientId
    AA_Certificate_bytes = pickle.dumps(AA_Certificate)
    json_AA_Certificate_bytes = json_custom(AA_Certificate_bytes)

    AA_id = sha3_256Hash(json_AA_Certificate_bytes)
    AA_id_json = json.dumps(AA_id)
    AA_id_trim = AA_id_json[:8]

    if(AA_id_trim != recipients['recipientId']):
        return "This is not the right AA"
    else:
        # Pasul 3 Se decripteaza ciphertext-ul folosind cheia privata a AA-ului
        f = open('C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\secp256r1privkeyAA.txt', 'rb')
        privkey_bytes = f.read()
        AA_privKey = pickle.loads(privkey_bytes)
        f.close()
       
       
        (V, c, t, salt) = ciphertext
        etsiTs103097Data_Signed_bytes = decrypt_ecies(V, c, t, salt, AA_privKey)

        # Pasul 3.1 Se extrage obiectul etsiTs103097Data_Signed
        etsiTs103097Data_Signed = pickle.loads(etsiTs103097Data_Signed_bytes)

        # Pasul 4 Se extrage obiectul etsiTs102941Data 
        # din tbsData din etsiTs103097Data_Signed de la pasul 3.1

        etsiTs102941Data = etsiTs103097Data_Signed.tbsData['payload']

        # Pasul 5 Se extrage obiectul innerATRequest din 
        # content din obiectul etsiTs102941Data de la pasul 4

        innerATRequest = etsiTs102941Data.content

        # Pasul 6 Se extrage cheia V_ef din publicKeys din innerATRequest
        # pentru a se verifica signature pentru obiectul de la pasul 3
        # etsiTs103097Data_Signed

        V_ef = innerATRequest.publicKeys[0]
        V_enc = innerATRequest.publicKeys[1]

        tbsData = etsiTs103097Data_Signed.tbsData
        tbsData_bytes = pickle.dumps(tbsData)
        json_tbsData_bytes = json_custom(tbsData_bytes)
        signature_to_verify = etsiTs103097Data_Signed.signature
        valid = verifyECDSAsecp256r1(json_tbsData_bytes, signature_to_verify, (V_ef.x, V_ef.y))
        
        if(valid != True):
            return "Something went wrong with the signature for tbsData from etsiTs103097Data_Signed"
        else:
            # Pasul 7 Se verifica keyTag-ul
            hmacKey = innerATRequest.hmacKey
            # Pasul 7.1 Se creeza un tag folosing functia de hash HMAC_SHA256 de cheile publice ef si enc serializate si concatenate

            # 7.2 Serializez cheile publice V_ef si V_enc

            V_ef_bytes = pickle.dumps(V_ef)
            V_enc_bytes = pickle.dumps(V_enc)

            # 7.3 Concatenez cele doua chei serializate

            V_concat = V_ef_bytes + V_enc_bytes

            # 7.4 Apelez functia de hash pentru a obtine un tag de 32 de bytes

            tag = generate_hmac(hmacKey, V_concat)
            tag = tag.digest()

            # 7.5 Trunchiez tag-ul la 16 bytes(128 bits to the leftmost)
            keyTag = tag[16:]

            # 7.6 Extrag obiectul sharedATRequest din innerATRequest

            sharedATRequest = innerATRequest.sharedATRequest

            keyTag_to_verify = sharedATRequest.keyTag

            if(keyTag != keyTag_to_verify):
                # TODO 
                # Return an AuthorizationResponse with negative response code different from 0
                return {'Something went wrong with verifying keyTags'}
            else:
                # TODO
                # AA -> EA AuthorizationValidationRequest asking for the authorization validation for the requeste AT
                # EA -> AA AuthorizationValidationResponse
                return {'hello': 1}






















app.run(port=5002)