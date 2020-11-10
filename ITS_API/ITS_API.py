from flask import Flask, request
import secrets
import sys
import pickle
import json
import base64
from tinyec import (registry, ec)
from Cryptodome.Random import get_random_bytes
from AESCCM import (encrypt_AESCCM, decrypt_AESCCM)
from ECIES import encrypt_ecies
from ECDSA import signECDSAsecp256r1, verifyECDSAsecp256r1
import requests


app = Flask(__name__)


@app.route('/EA/Enrolment', methods=['POST'])
def ITS_Enrolment():
    reqData = request.get_json()
    print(reqData)
    return f"OK {reqData}"


def generateKeyPair_secp256r1():
    curve = registry.get_curve('secp256r1')
    r = secrets.randbelow(curve.field.n)
    V = r * curve.g
    return (r, V)


def eciesEncription(message):
    return message


def xor_strings(s, t) -> bytes:
    """xor two strings together."""
    if isinstance(s, str):
        # Text strings contain single characters
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
    else:
        # Python 3 bytes objects contain integer values in the range 0-255
        return bytes([a ^ b for a, b in zip(s, t)])


def xor2_strings(s, t) -> bytes:
    while(len(s) > len(t)):
        t = t + t[:(len(s)-len(t))]

    if(len(s) < len(t)):
        t = t[:len(s)]
        return xor_strings(s, t)
    else:
        return xor_strings(s, t)


def json_custom(x):
    """
    x has to be bytes
    """
    base64_x_bytes = base64.b64encode(x)
    base64_x_message = base64_x_bytes.decode('ascii')
    base64_x_message = json.dumps(base64_x_message)
    return base64_x_message


class InnerEcRequest:
    def __init__(self, itsId, certificateFormat, verificationKey, requestedSubjectAttributes):
        self.itsId = itsId
        self.certificateFormat = certificateFormat
        self.verificationKey = verificationKey
        self.requestedSubjectAttributes = requestedSubjectAttributes


class EtsiTs103097Data_Signed:
    def __init__(self, hashId, tbsData, signer, signature):
        self.hashId = hashId
        self.tbsData = tbsData
        self.signer = signer
        self.signature = signature


class EtsiTs102941Data:
    def __init__(self, version, content):
        self.version = version
        self.content = content


class EtsiTs103097Data_Encrypted:
    def __init__(self, recipients, ciphertext):
        self.recipients = recipients
        self.ciphertext = ciphertext

# Enrolment pentru prima data la EA: ITS -> EA
# Pasul 1
# Creez un InnerEcRequest


f = open("./secp256r1pubkeyITS.txt", 'rb')
ITS_pubkey_bytes = f.read()
ITS_pubkey = pickle.loads(ITS_pubkey_bytes)
f.close()
f = open("./secp256r1privkeyITS.txt", 'rb')
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
f = open("../EA_API/secp256r1pubkeyEA.txt", 'rb')
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

f = open('../EA_API/secp256r1pubkeyEA.txt', 'rb')
pubkey_bytes = f.read()
EA_pubKey = pickle.loads(pubkey_bytes)
f.close()

(V, c, t, salt) = encrypt_ecies(
    cipher_etsiTs103097Data_Encrypted_bytes['AES-Key'], EA_pubKey)
print(cipher_etsiTs103097Data_Encrypted_bytes['AES-Key'])
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

# sending post request and saving response as response object
r = requests.post(url=API_ENDPOINT, json=data)

# extracting response text
pastebin_url = r.text
print("The pastebin URL is:%s" % pastebin_url)


app.run(port=5000)
