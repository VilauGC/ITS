import sys
sys.path.append("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\UTILS")

from flask import Flask, request
import secrets
import sys
import pickle
import json
import base64
from tinyec import (registry, ec)
from Cryptodome.Random import get_random_bytes
from AESCCM import (encrypt_AESCCM, decrypt_AESCCM)
from ECIES import (encrypt_ecies, decrypt_ecies)
from ECDSA import signECDSAsecp256r1, verifyECDSAsecp256r1
import requests
from models import (EtsiTs102941Data, EtsiTs103097Data_Encrypted, EtsiTs103097Data_Signed, ExplicitCertificate, InnerEcRequest, InnerEcResponse)
from functions import (json_custom, json_to_bytes)
from authorizationRequest import make_authorization_request

app = Flask(__name__)


@app.route('/EA/Enrolment', methods=['POST'])
def ITS_Enrolment():
    reqData = request.get_json()
    print(reqData)
    return f"OK {reqData}"

# Enrolment pentru prima data la EA: ITS -> EA
# Pasul 1
# Creez un InnerEcRequest


f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\ITS_API\\secp256r1pubkeyITS.txt", 'rb')
ITS_pubkey_bytes = f.read()
ITS_pubkey = pickle.loads(ITS_pubkey_bytes)
f.close()
f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\ITS_API\\secp256r1privkeyITS.txt", 'rb')
ITS_privkey_bytes = f.read()
ITS_privkey = pickle.loads(ITS_privkey_bytes)
f.close()


itsId = 'Lamborghini'
# itsId = 'RenaultClio'
certificateFormat = 'ts103097v131'
# transform in bytes cheia publica care este de tipul POINT
verificationKey = pickle.dumps(ITS_pubkey)
requestedSubjectAttributes = ''


innerEcRequest = InnerEcRequest(
    itsId, certificateFormat, verificationKey, requestedSubjectAttributes)

# Pasul 2
# Creez un EtsiTs103097Data_Signed

# De completat cu numele algoritmului de hash folosit pentru semnarea ECDSA a lui tbsData
hashId = 'sha3-256'
# pentru simplificare am lasat headerInfo gol
tbsData = {'payload': innerEcRequest, 'headerInfo': ''}
tbsData_bytes = pickle.dumps(tbsData)
json_tbsData_bytes = json_custom(tbsData_bytes)
signer = 'self'
signature = signECDSAsecp256r1(json_tbsData_bytes, ITS_privkey)

etsiTs103097Data_Signed = EtsiTs103097Data_Signed(
    hashId, tbsData, signer, signature)


# Pasul 3
# Creez un EtsiTs102941Data

version = '1'
content = etsiTs103097Data_Signed

etsiTs102941Data = EtsiTs102941Data(version, content)

# Pasul 4
# Creez un EtsiTs103097Data_Signed
hashId = ''
tbsData = {'payload': etsiTs102941Data, 'headerInfo': ''}
tbsData_bytes = pickle.dumps(tbsData)
json_tbsData_bytes = json_custom(tbsData_bytes)
signer = 'self'
signature = signECDSAsecp256r1(json_tbsData_bytes, ITS_privkey)

etsiTs103097Data_Signed = EtsiTs103097Data_Signed(
    hashId, tbsData, signer, signature)


# Pasul 5
# Creez un EtsiTs103097Data_Encrypted

# Citesc cheia publica a EA-ului pentru a o folosi in criptare ecies a lui etsiTs103097Data_Signed
f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\secp256r1pubkeyEA.txt", 'rb')
pubkey_bytes = f.read()
EA_pubKey = pickle.loads(pubkey_bytes)
f.close()
etsiTs103097Data_Signed_bytes = pickle.dumps(etsiTs103097Data_Signed)
recipients = EA_pubKey
(V, c, t, salt) = encrypt_ecies(etsiTs103097Data_Signed_bytes, EA_pubKey)
ciphertext = (V, c, t.digest(), salt)

etsiTs103097Data_Encrypted = EtsiTs103097Data_Encrypted(recipients, ciphertext)


# Pasul 6
# Criptez obiectul etsiTs103097Data_Encrypted cu AES-CCM


# Transform obiectul in bytes
etsiTs103097Data_Encrypted_bytes = pickle.dumps(etsiTs103097Data_Encrypted)

cipher_etsiTs103097Data_Encrypted_bytes = encrypt_AESCCM(
    etsiTs103097Data_Encrypted_bytes)


# Pasul 7
# Criptez cheia AES-CCM cu algorimul ECIES

f = open('C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\secp256r1pubkeyEA.txt', 'rb')
pubkey_bytes = f.read()
EA_pubKey = pickle.loads(pubkey_bytes)
f.close()

(V, c, t, salt) = encrypt_ecies(
    cipher_etsiTs103097Data_Encrypted_bytes['AES-Key'], EA_pubKey)
# Pasul 8
# Formez obiectul JSON care va fi pus in body-ul request-lui http catre EA API

json_c = json_custom(c)
json_salt = json_custom(salt)
json_cipher = json_custom(
    cipher_etsiTs103097Data_Encrypted_bytes['ciphertext'])
json_tag = json_custom(cipher_etsiTs103097Data_Encrypted_bytes['auth-tag'])
json_header = json_custom(cipher_etsiTs103097Data_Encrypted_bytes['header'])
json_nonce = json_custom(cipher_etsiTs103097Data_Encrypted_bytes['nonce'])
json_V = json_custom(pickle.dumps(V))
json_t = json_custom(t.digest())

# Pasul 9
# Trimit requestul prin http cu method POST

# defining the api-endpoint
API_ENDPOINT = "http://127.0.0.1:5001/its-enrolment"

# data to be sent to api
data = {'c': json_c, 'V': json_V, 't': json_t,
        'salt': json_salt, 'ciphertext': json_cipher,
        'nonce': json_nonce,
        'header': json_header,
        'tag': json_tag}

# sending post request to http://127.0.0.1:5001/its-enrolment
r = requests.post(url=API_ENDPOINT, json=data)

data_response = json.loads(r.text)

# Pasul 1 dupa EA RESPONSE

response_cipher_bytes = json_to_bytes(data_response['ciphertext'])
response_nonce_bytes = json_to_bytes(data_response['nonce'])
response_header_bytes = json_to_bytes(data_response['header'])
response_tag_bytes = json_to_bytes(data_response['tag'])

etsiTs103097Data_Encrypted_bytes = decrypt_AESCCM(
    cipher_etsiTs103097Data_Encrypted_bytes['AES-Key'],
    response_nonce_bytes,
    response_cipher_bytes,
    response_tag_bytes,
    response_header_bytes)

etsiTs103097Data_Encrypted = pickle.loads(etsiTs103097Data_Encrypted_bytes)
(V, c, t_digest, salt) = etsiTs103097Data_Encrypted.ciphertext

# Pasul 2 dupa EA RESPONSE formam un obiect etsiTs103097Data-Signed

etsiTs103097Data_Signed_bytes = decrypt_ecies(
    V, c, t_digest, salt, ITS_privkey)
etsiTs103097Data_Signed = pickle.loads(etsiTs103097Data_Signed_bytes)

# Pasul 3 verificam semnatura ecdsa pentru tbsData

tbsData = etsiTs103097Data_Signed.tbsData
tbsData_bytes = pickle.dumps(tbsData)
json_tbsData_bytes = json_custom(tbsData_bytes)
is_signature = verifyECDSAsecp256r1(
    json_tbsData_bytes, etsiTs103097Data_Signed.signature, (EA_pubKey.x, EA_pubKey.y))

# Pasul 4 extragem obiectul de tip etsiTs102941Data din tbsData['payload']

etsiTs102941Data = tbsData['payload']

# Pasul 5 extragem din etsiTs102941Data content-ul care contine InnerEcResponse

innerEcResponse = etsiTs102941Data.content

# Pasul 6 extragem certificatul ITS-ului semnat de catre EA

ITS_Signed_Certificate = innerEcResponse.certificate
print(ITS_Signed_Certificate)

test = make_authorization_request(ITS_Signed_Certificate, ITS_privkey)
print(test)

app.run(port=5000)
