"""
Authorization Request sent by ITS after receiving EC from EA after a successful Enrolment Request

"""
from functions import (generateKeyPair_secp256r1, generate_hmac, json_custom)
from models import (SharedATRequest, EtsiTs103097Data_SignedExternalPayload)
from ECDSA import (sha3_256Hash, signECDSAsecp256r1)
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
    print(signer)
    signature = signECDSAsecp256r1(json_tbsData_bytes, ITS_privKey)

    etsiTs103097Data_SignedExternalPayload = EtsiTs103097Data_SignedExternalPayload(
        hashId, tbsData, signer, signature)

    return etsiTs103097Data_SignedExternalPayload
