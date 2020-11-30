import sys
sys.path.append("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\UTILS")

from flask import Flask, request
from ECIES import (decrypt_ecies, encrypt_ecies)
from AESCCM import (decrypt_AESCCM, encrypt_AESCCM, encrypt_AESCCM_withKey)
from ECDSA import (verifyECDSAsecp256r1, signECDSAsecp256r1)
from functions import (json_to_bytes, json_custom, sha3_256Hash)
from models import (ExplicitCertificate, 
InnerEcResponse, 
EtsiTs102941Data, 
EtsiTs103097Data_Signed,
EtsiTs103097Data_Encrypted)
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

        # 1.2 TODO Se salveaza certificatul intr-un fisier enrolment_certificates

        hashCertificate = sha3_256Hash(json_custom(pickle.dumps(its_certificate)))

        f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\ITS_Certificates.txt", 'wb')
        f.write(pickle.dumps(hashCertificate))
        f.close()

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

@app.route('/authorizationValidation', methods=['POST'])
def authorizationValidation():
    req_json = request.get_json()
    etsiTs103097Data_Encrypted = pickle.loads(json_to_bytes(req_json))

    # Pasul 1 Scot cipherul cheii AES din recipients encKey din etsiTs103097Data_Encrypted

    encKey = etsiTs103097Data_Encrypted.recipients['encKey']

    (V, c, t_digest, salt) = encKey

    # Pasul 2 Decriptam c din encKey pentru a obtine cheia AES decrypt_ecies
    f = open('C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\secp256r1privkeyEA.txt', 'rb')
    privkey_bytes = f.read()
    EA_privkey = pickle.loads(privkey_bytes)
    f.close()

    aesKey = decrypt_ecies(V, c, t_digest, salt, EA_privkey)

    # Pasul 3 Cu cheia aesKey de la pasul 2 decriptam ciphertextul din etsiTs103097Data_Encrypted

    ciphertext = etsiTs103097Data_Encrypted.ciphertext

    cipher_to_decrypt = ciphertext['ciphertext']
    auth_tag = ciphertext['auth-tag']
    nonce = ciphertext['nonce']
    header = ciphertext['header']

    etsiTs103097Data_Signed_bytes = decrypt_AESCCM(aesKey, nonce, cipher_to_decrypt, auth_tag, header)

    etsiTs103097Data_Signed = pickle.loads(etsiTs103097Data_Signed_bytes)

    # Pasul 4 Se verifica semnatura pentru tbsData, signature from etsiTs103097Data_Signed

    # 4.1 Se preia cheia publica din certificatul AA-ului

    f = open(
        "C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\AA_Certificate.txt", 'rb')
    AA_Certificate_bytes = f.read()
    AA_Certificate = pickle.loads(AA_Certificate_bytes)
    f.close()

    AA_pubKey = AA_Certificate.toBeSigned['verifyKeyIndicator']['verificationKey']

    # 4.2 Se verifica semnatura cu ecdsa_verify

    tbsData = etsiTs103097Data_Signed.tbsData
    tbsData_bytes = pickle.dumps(tbsData)
    json_tbsData_bytes = json_custom(tbsData_bytes)

    print(len(json_tbsData_bytes))
    signature_to_verify = etsiTs103097Data_Signed.signature
    valid = verifyECDSAsecp256r1(json_tbsData_bytes, signature_to_verify, (AA_pubKey.x, AA_pubKey.y))

    if(valid != True):
        return "Something went wrong with the signature for tbsData from etsiTs103097Data_Signed"
    else:
        
        # Pasul 5 Se extrage obiectul etsiTs102941Data din payload-ul lui tbsData

        etsiTs102941Data = etsiTs103097Data_Signed.tbsData['payload']

        # Pasul 6 Se extrage obiectul de tipul AuthorizationValidationRequest

        authorizationValidationRequest = etsiTs102941Data.content

        # Pasul 7 Se extrag obiectele sharedATRequest si ecSignature

        sharedATRequest = authorizationValidationRequest.sharedATRequest

        ecSignature = authorizationValidationRequest.ecSignature

        # Pasul 8 Se verifica ecSignature
        # TODO
        # Verific daca hash-ul EC emis pentru its este acelasi cu cel din signer
        # Verific daca semnatura este facuta cu cheia publica din certificatul EC

        # Pasul 9 Se formeaza un AuthorizationValidationResponse

        return 'Inside ELSE'



app.run(port=5001)
