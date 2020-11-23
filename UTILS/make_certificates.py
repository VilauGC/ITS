import pickle
from functions import json_custom
from ECDSA import signECDSAsecp256r1
from models import ExplicitCertificate

def createCertificate(publicKeyOfEntity, RCA_privKey):
    _type = 'explicit'
    toBeSigned = {'verifyKeyIndicator': {
        'verificationKey': publicKeyOfEntity}}

    toBeSigned_bytes = pickle.dumps(toBeSigned)
    json_toBeSigned_bytes = json_custom(toBeSigned_bytes)

    signature = signECDSAsecp256r1(json_toBeSigned_bytes, RCA_privKey)

    certificate = ExplicitCertificate(_type, toBeSigned, signature)

    return certificate


f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\RootCA\\secp256r1privkeyRCA.txt", 'rb')
RootCA_privkey_bytes = f.read()
RCA_privKey = pickle.loads(RootCA_privkey_bytes)
f.close()


# Make certificates for EA and AA signed by the RootCA using the keys from RootCA folder
f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\secp256r1pubkeyEA.txt", 'rb')
EA_pubkey_bytes = f.read()
EA_pubkey = pickle.loads(EA_pubkey_bytes)
f.close()

f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\secp256r1pubkeyAA.txt", 'rb')
AA_pubkey_bytes = f.read()
AA_pubkey = pickle.loads(AA_pubkey_bytes)
f.close()

EA_certificate = createCertificate(EA_pubkey, RCA_privKey)
AA_certificate = createCertificate(AA_pubkey, RCA_privKey)

f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\EA_Certificate.txt", 'wb')
f.write(pickle.dumps(EA_certificate))
f.close()

f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\AA_Certificate.txt", 'wb')
f.write(pickle.dumps(AA_certificate))
f.close()

