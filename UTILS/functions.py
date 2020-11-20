from tinyec import (registry, ec)
import secrets
import base64
import json
import hashlib
import hmac


def generateKeyPair_secp256r1():
    curve = registry.get_curve('secp256r1')
    r = secrets.randbelow(curve.field.n)
    V = r * curve.g
    return (r, V)


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


def json_to_bytes(x):
    """
    x is str type
    """
    base64_x_message = json.loads(x)
    base64_x_message = base64_x_message.encode('ascii')
    message_bytes = base64.b64decode(base64_x_message)

    return message_bytes

def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")

def generate_hmac(Km, c):
    t = hmac.new(Km, c, hashlib.sha256)
    return t