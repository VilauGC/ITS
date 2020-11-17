import hashlib

from pycoin.ecdsa.Generator import Generator
from pycoin.ecdsa.secp256r1 import secp256r1_generator


def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")


def signECDSAsecp256r1(msg, privKey):
    msgHash = sha3_256Hash(msg)
    signature = Generator.sign(secp256r1_generator, privKey, msgHash)
    return signature


def verifyECDSAsecp256r1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    valid = Generator.verify(secp256r1_generator, pubKey, msgHash, signature)
    return valid

# Testing the functions
# ECDSA sign message (using the curve secp256r1 + SHA3-256)
# msg = "Message for ECDSA signing"
# privKey = secrets.randbelow(secp256r1_generator.order())
# signature = signECDSAsecp256k1(msg, privKey)
# print("Message:", msg)
# print("Private key:", hex(privKey))
# print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))

# # ECDSA verify signature (using the curve secp256k1 + SHA3-256)
# pubKey = secp256r1_generator * privKey
# valid = verifyECDSAsecp256k1(msg, signature, pubKey)
# print("\nMessage:", msg)
# print("Public key: (" + hex(pubKey[0]) + ", " + hex(pubKey[1]) + ")")
# print("Signature valid?", valid)

# # ECDSA verify tampered signature (using the curve secp256k1 + SHA3-256)
# msg = "Tampered message"
# valid = verifyECDSAsecp256k1(msg, signature, pubKey)
# print("\nMessage:", msg)
# print("Signature (tampered msg) valid?", valid)
