"""
Checks if a certificate hash is present in the database of the EA;
Returns the public key_bytes of a hash certificate

"""



from functions import json_custom, sha3_256Hash
import json
import pickle


def checkCertHash(certHash):
    f = open('C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\ITS_certificates.txt', 'rb')
    its_certificate_bytes = f.read()
    f.close()

    json_its_certificate_bytes = json_custom(its_certificate_bytes)
    itsCertHash = sha3_256Hash(json_its_certificate_bytes)
    itsCertHash_json = json.dumps(itsCertHash)
    itsCertHash = itsCertHash_json[:8]
    if(certHash == itsCertHash):
        return True
    else: 
        return False

def getPubKeyForHashCertificate(certHash):
    f = open('C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\EA_API\\ITS_certificates.txt', 'rb')
    its_certificate_bytes = f.read()
    f.close()

    its_certificate = pickle.loads(its_certificate_bytes)

    json_its_certificate_bytes = json_custom(its_certificate_bytes)
    itsCertHash = sha3_256Hash(json_its_certificate_bytes)
    itsCertHash_json = json.dumps(itsCertHash)
    itsCertHash = itsCertHash_json[:8]
    if(certHash == itsCertHash):
        return its_certificate.toBeSigned['verifyKeyIndicator']['verificationKey']
    else: 
        return False