"""
Authorization Request sent by ITS after receiving EC from EA after a successful Enrolment Request

"""
from functions import (generateKeyPair_secp256r1, generate_hmac, json_custom)
from models import (SharedATRequest,
                    EtsiTs103097Data_SignedExternalPayload,
                    EtsiTs103097Data_Encrypted,
                    InnerATRequest,
                    EtsiTs102941Data,
                    EtsiTs103097Data_Signed)
from ECDSA import (sha3_256Hash, signECDSAsecp256r1)
from ECIES import encrypt_ecies
from AESCCM import encrypt_AESCCM
from Cryptodome.Random import get_random_bytes
import pickle
import json


def make_authorization_request(EC_Certificate, ITS_privKey):
    # Pasul 1
    # Se creeaza o pereche de chei care se va crea pentru fiecare authorization request

    (r_ef, V_ef) = generateKeyPair_secp256r1()

    # Pasul 2 Optional in cazul in care avem nevoie de privacy pentru ITS-ul nostru

    (r_enc, V_enc) = generateKeyPair_secp256r1()

    # Pasul 3 Se genereaza un hmac-key (secret) de 32 bytes

    hmac_key = get_random_bytes(32)

    # Pasul 4 Se creeza un tag folosing functia de hash HMAC_SHA256 de cheile publice ef si enc serializate si concatenate

    # 4.1 Serializez cheile publice V_ef si V_enc

    V_ef_bytes = pickle.dumps(V_ef)
    V_enc_bytes = pickle.dumps(V_enc)

    # 4.2 Concatenez cele doua chei serializate

    V_concat = V_ef_bytes + V_enc_bytes

    # 4.3 Apelez functia de hash pentru a obtine un tag de 32 de bytes

    tag = generate_hmac(hmac_key, V_concat)
    tag = tag.digest()

    # 4.4 Trunchiez tag-ul la 16 bytes(128 bits to the leftmost)
    keyTag = tag[16:]

    # Pasul 5 Se creeaza un obiect de tip SharedATRequest
    # 5.1 Se citeste certificatul EA-ului

    f = open(
        "C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\EA_Certificate.txt", 'rb')
    EA_Certificate_bytes = f.read()
    EA_Certificate = pickle.loads(EA_Certificate_bytes)
    f.close()
    # 5.2 Se formeaza SharedATRequest
    eaId = EA_Certificate
    KeyTag = keyTag
    certificateFormat = 'ts103097v131'
    requestedSubjectAttributes = ''

    sharedATRequest = SharedATRequest(
        eaId, KeyTag, certificateFormat, requestedSubjectAttributes)

    # Pasul 6 Se creeaza un obiect de tip EtsiTs103097Data_SignedExternalPayload

    hashId = 'SHA256'

    sharedATRequest_bytes = pickle.dumps(sharedATRequest)
    json_sharedATRequest_bytes = json_custom(sharedATRequest_bytes)
    tbsData = {'payload': {'extDataHash': sha3_256Hash(
        json_sharedATRequest_bytes)}, 'headerInfo': ''}

    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)

    EC_Certificate_bytes = pickle.dumps(EC_Certificate)
    json_EC_Certificate_bytes = json_custom(EC_Certificate_bytes)

    signer = sha3_256Hash(json_EC_Certificate_bytes)
    signer_json = json.dumps(signer)

    signer = signer_json[:8]  # hashedId8
    signature = signECDSAsecp256r1(json_tbsData_bytes, ITS_privKey)

    etsiTs103097Data_SignedExternalPayload = EtsiTs103097Data_SignedExternalPayload(
        hashId, tbsData, signer, signature)

    # Pasul 7 Se creeaza un obiect de tip EtsiTs103097Data_Encrypted peste EtsiTs103097Data_SignedExternalPayload
    # Acesta poarta numele de ecSignature

    # Pasul 7.1 Se creeaza un hash pentru certificatul EA-ului
    EA_Certificate_bytes = pickle.dumps(EA_Certificate)
    json_EA_Certificate_bytes = json_custom(EA_Certificate_bytes)

    recipientId = sha3_256Hash(json_EA_Certificate_bytes)
    recipientId_json = json.dumps(recipientId)
    recipientId = recipientId_json[:8]

    # Pasul 7.2 Se cripteaza EtsiTs103097Data_SignedExternalPayload cu algoritmul AESCCM

    etsiTs103097Data_SignedExternalPayload_bytes = pickle.dumps(etsiTs103097Data_SignedExternalPayload)

    dataAESCCM_ec = encrypt_AESCCM(etsiTs103097Data_SignedExternalPayload_bytes)

    AES_Key_ec = dataAESCCM_ec['AES-Key']

    del dataAESCCM_ec['AES-Key']

    ciphertext = dataAESCCM_ec

    # Pasul 7.3 Criptam cheia AESKEY folosita la 7.2 cu ECIES si o punem in encKey din recipients

    EA_pubKey = EA_Certificate.toBeSigned['verifyKeyIndicator']['verificationKey']

    (V, c, t, salt) = encrypt_ecies(AES_Key_ec, EA_pubKey)

    encKey = (V, c, t.digest(), salt)

    recipients = {'recipientId': recipientId, 'encKey': encKey}

    etsiTs103097Data_Encrypted_ec = EtsiTs103097Data_Encrypted(recipients, ciphertext)
    
    ecSignature = pickle.dumps(etsiTs103097Data_Encrypted_ec)

    # Pasul 8 Se creeaza un obiect de tipul InnerATRequest

    publicKeys = (V_ef, V_enc)
    hmacKey = hmac_key
    innerATRequest = InnerATRequest(
        publicKeys, hmacKey, sharedATRequest, ecSignature)

    # Pasul 9 Se creeaza un obiect de tipul EtsiTs102941Data

    version = 1
    content = innerATRequest

    etsiTs102941Data = EtsiTs102941Data(version, content)

    # Pasul 10 Se creeaza un obiect de tipul EtsiTs103097Data_Signed Obs: Acesta este optional

    hashId = 'SHA256'
    tbsData = {'payload': etsiTs102941Data, 'headerInfo': ''}
    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)

    signature = signECDSAsecp256r1(json_tbsData_bytes, r_ef)
    signer = 'self'

    etsiTs103097Data_Signed = EtsiTs103097Data_Signed(hashId, tbsData, signer, signature)

    # Pasul 11 Se creeaza un obiect EtsiTs103097Data_Encrypted peste EtsiTs103097Data_Signed

    # 11.1 Se citeste certificatul AA-ului

    f = open(
        "C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\AA_Certificate.txt", 'rb')
    AA_Certificate_bytes = f.read()
    AA_Certificate = pickle.loads(AA_Certificate_bytes)
    f.close()
    
    # Pasul 11.2 Se creeaza un hash pentru certificatul AA-ului
    AA_Certificate_bytes = pickle.dumps(AA_Certificate)
    json_AA_Certificate_bytes = json_custom(AA_Certificate_bytes)

    recipientId = sha3_256Hash(json_AA_Certificate_bytes)
    recipientId_json = json.dumps(recipientId)
    recipientId = recipientId_json[:8]
    
    AA_pubKey = AA_Certificate.toBeSigned['verifyKeyIndicator']['verificationKey']

    # Pasul 11.3 Se cripteaza EtsiTs103097Data_Signed cu alg. AESCCM 

    etsiTs103097Data_Signed_bytes = pickle.dumps(etsiTs103097Data_Signed)

    dataAESCCM = encrypt_AESCCM(etsiTs103097Data_Signed_bytes)

    AES_Key = dataAESCCM['AES-Key']

    del dataAESCCM['AES-Key']

    ciphertext = dataAESCCM

    # Pasul 11.4 Criptam cheia AESKEY folosita la 11.3 cu ECIES si o punem in encKey din recipients

    (V, c, t, salt) = encrypt_ecies(AES_Key, AA_pubKey)

    encKey = (V, c, t.digest(), salt)

    recipients = {'recipientId': recipientId, 'encKey': encKey}

    etsiTs103097Data_Encrypted = EtsiTs103097Data_Encrypted(recipients, ciphertext)
    
    return (etsiTs103097Data_Encrypted, AES_Key, r_enc)
