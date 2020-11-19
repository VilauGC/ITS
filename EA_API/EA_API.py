import sys
sys.path.append("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\UTILS")

from flask import Flask, request
from ECIES import (decrypt_ecies, encrypt_ecies)
from AESCCM import (decrypt_AESCCM, encrypt_AESCCM, encrypt_AESCCM_withKey)
from ECDSA import (verifyECDSAsecp256r1, signECDSAsecp256r1)
import json
import base64
import pickle
import hashlib

app = Flask(__name__)

allowedITS = ['RenaultClio', 'Mercedes', 'Bmw', 'Lamborghini']


@app.route('/its-enrolment', methods=['POST'])
def its_enrolment():
    req_json = request.get_json()
    V = req_json["V"]
    t = req_json["t"]
    c = req_json["c"]
    salt = req_json["salt"]
    ciphertext = req_json["ciphertext"]
    tag = req_json["tag"]
    header = req_json["header"]
    nonce = req_json["nonce"]
    # reconstruim informatia la nivel de bytes
    V = json_to_bytes(V)
    V_inf = pickle.loads(V)
    t_digest = json_to_bytes(t)
    c = json_to_bytes(c)
    salt = json_to_bytes(salt)
    ciphertext_ccm = json_to_bytes(ciphertext)
    tag_ccm = json_to_bytes(tag)
    header_ccm = json_to_bytes(header)
    nonce_ccm = json_to_bytes(nonce)
    # f = open('./secp256r1privkeyEA.txt', 'rb')
    f = open('C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\secp256r1privkeyEA.txt', 'rb')
    privkey_bytes = f.read()
    EA_privkey = pickle.loads(privkey_bytes)
    f.close()
    AES_CCM_KEY = decrypt_ecies(V_inf, c, t_digest, salt, EA_privkey)
    etsiTs103097Data_Encrypted_bytes = decrypt_AESCCM(
        AES_CCM_KEY, nonce_ccm, ciphertext_ccm, tag_ccm, header_ccm)

    etsiTs103097Data_Encrypted = pickle.loads(etsiTs103097Data_Encrypted_bytes)

    (V2, c2, t2, salt2) = etsiTs103097Data_Encrypted.ciphertext

    etsiTs103097Data_Signed_bytes = decrypt_ecies(
        V2, c2, t2, salt2, EA_privkey)
    etsiTs103097Data_Signed = pickle.loads(etsiTs103097Data_Signed_bytes)

    # get the ITS pub key
    # Aici ar trebui mai intai sa scot cheia publica a ITS-ului si mai apoi sa fac verificarile
    # Dar pentru simplificare am luat cheia din fisier

    # f = open("../ITS_API/secp256r1pubkeyITS.txt", 'rb')
    f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\ITS_API\\secp256r1pubkeyITS.txt", 'rb')
    ITS_pubkey_bytes = f.read()
    ITS_pubkey = pickle.loads(ITS_pubkey_bytes)
    f.close()

    # verify the signature
    tbsData = etsiTs103097Data_Signed.tbsData
    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)
    is_signature = verifyECDSAsecp256r1(
        json_tbsData_bytes, etsiTs103097Data_Signed.signature, (ITS_pubkey.x, ITS_pubkey.y))

    # get the etsiTs102941Data

    etsiTs102941Data = tbsData['payload']

    # get the inner etsiTs103097Data_Signed

    inner_etsiTs103097Data_Signed = etsiTs102941Data.content
    inner_tbsData = inner_etsiTs103097Data_Signed.tbsData
    inner_tbsData_bytes = pickle.dumps(inner_tbsData)
    json_inner_tbsData_bytes = json_custom(inner_tbsData_bytes)
    inner_is_signature = verifyECDSAsecp256r1(
        json_inner_tbsData_bytes, inner_etsiTs103097Data_Signed.signature, (ITS_pubkey.x, ITS_pubkey.y))

    # get the innerEcRequest

    innerEcRequest = inner_tbsData['payload']
    # get the ITS publickey from InnerEcRequest
    inner_its_publicKey = innerEcRequest.verificationKey
    # get the itsId

    itsId = innerEcRequest.itsId

    if(itsId in allowedITS):

        # Pasul 1 in formarea unui Response
        # Se formeaza un obiect de tip InnerEcResponse
        json_etsiTs103097Data_Encrypted = json_custom(
            etsiTs103097Data_Encrypted_bytes)
        requestHash = sha3_256Hash(json_etsiTs103097Data_Encrypted)
        responseCode = 0

        # 1.1 Se formeaza certificatul ITS-ului
        _type = 'explicit'
        toBeSigned = {'verifyKeyIndicator': {
            'verificationKey': inner_its_publicKey}}

        toBeSigned_bytes = pickle.dumps(toBeSigned)
        json_toBeSigned_bytes = json_custom(toBeSigned_bytes)

        signature = signECDSAsecp256r1(json_toBeSigned_bytes, EA_privkey)

        its_certificate = ExplicitCertificate(_type, toBeSigned, signature)

        innerEcResponse = InnerEcResponse(
            requestHash, responseCode, its_certificate)

        # Pasul 2
        # Se formeaza un obiect de tip EtsiTs102941Data

        version = 1
        content = innerEcResponse

        etsiTs102941Data = EtsiTs102941Data(version, content)

        # Pasul 3
        # Se formeaza un obiect de tip EtsiTs103097Data-Signed
        hashId = 'SHA3-256'
        tbsData = {'payload': etsiTs102941Data, 'headerInfo': ''}
        tbsData_bytes = pickle.dumps(tbsData)
        json_tbsData_bytes = json_custom(tbsData_bytes)
        signer = ''
        signature = signECDSAsecp256r1(json_tbsData_bytes, EA_privkey)

        etsiTs103097Data_Signed = EtsiTs103097Data_Signed(
            hashId, tbsData, signer, signature)

        # Pasul 4
        # Se formeaza un obiect de tip EtsiTs103097Data-Encrypted
        etsiTs103097Data_Signed_bytes = pickle.dumps(etsiTs103097Data_Signed)
        recipients = ''
        (V, c, t, salt) = encrypt_ecies(
            etsiTs103097Data_Signed_bytes, ITS_pubkey)
        cipherText = (V, c, t.digest(), salt)

        etsiTs103097Data_Encrypted = EtsiTs103097Data_Encrypted(
            recipients, cipherText)

        # Pasul 5
        # Criptez obiectul etsiTs103097Data_Encrypted cu aceeasi cheie AES-CCM

        etsiTs103097Data_Encrypted_bytes = pickle.dumps(
            etsiTs103097Data_Encrypted)

        cipher_etsiTs103097Data_Encrypted_bytes = encrypt_AESCCM_withKey(
            etsiTs103097Data_Encrypted_bytes, AES_CCM_KEY)

        json_cipher = json_custom(
            cipher_etsiTs103097Data_Encrypted_bytes['ciphertext'])
        json_tag = json_custom(
            cipher_etsiTs103097Data_Encrypted_bytes['auth-tag'])
        json_header = json_custom(
            cipher_etsiTs103097Data_Encrypted_bytes['header'])
        json_nonce = json_custom(
            cipher_etsiTs103097Data_Encrypted_bytes['nonce'])

        response_data = {'ciphertext': json_cipher,
                         'nonce': json_nonce,
                         'header': json_header,
                         'tag': json_tag}
        json_response_data = json.dumps(response_data)

        return response_data
    else:
        print("No such ITS found!")
        return "No such ITS found!"


class InnerEcRequest:
    def __init__(self, itsId, certificateFormat, verificationKey, requestedSubjectAttributes):
        self.itsId = itsId
        self.certificateFormat = certificateFormat
        self.verificationKey = verificationKey
        self.requestedSubjectAttributes = requestedSubjectAttributes


class InnerEcResponse:
    def __init__(self, requestHash, responseCode, certificate):
        self.requestHash = requestHash
        self.responseCode = responseCode
        self.certificate = certificate


class EtsiTs102941Data:
    def __init__(self, version, content):
        self.version = version
        self.content = content


class EtsiTs103097Data_Signed:
    def __init__(self, hashId, tbsData, signer, signature):
        self.hashId = hashId
        self.tbsData = tbsData
        self.signer = signer
        self.signature = signature


class EtsiTs103097Data_Encrypted:
    def __init__(self, recipients, ciphertext):
        self.recipients = recipients
        self.ciphertext = ciphertext


class ExplicitCertificate:
    def __init__(self, _type, toBeSigned, signature):
        self.type = _type
        self.toBeSigned = toBeSigned
        self.signature = signature


def json_to_bytes(x):
    """
    x is str type
    """
    base64_x_message = json.loads(x)
    base64_x_message = base64_x_message.encode('ascii')
    message_bytes = base64.b64decode(base64_x_message)

    return message_bytes


def json_custom(x):
    """
    x has to be bytes
    """
    base64_x_bytes = base64.b64encode(x)
    base64_x_message = base64_x_bytes.decode('ascii')
    base64_x_message = json.dumps(base64_x_message)
    return base64_x_message


def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")


app.run(port=5001)
