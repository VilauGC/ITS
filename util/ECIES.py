import hashlib
import hmac
import secrets

from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes
from tinyec import registry

curve = registry.get_curve('secp256r1')


def generate_ephemeral_keyPair():
    r = secrets.randbelow(curve.field.n)
    V = r * curve.g
    return (r, V)


def generate_shared_secret(ephemeralPrivKey, publicKeyOfReceiver):
    sharedSecret = ephemeralPrivKey * publicKeyOfReceiver
    return sharedSecret.x


def key_derivation_func(sharedSecret, salt):
    keyKDF = scrypt(hex(sharedSecret), salt, 48, N=2 ** 14, r=8, p=1)
    Ke = keyKDF[:16]
    Km = keyKDF[16:]
    return (Ke, Km)


def xor_strings(s, t) -> bytes:
    """xor two strings together."""
    if isinstance(s, str):
        # Text strings contain single characters
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
    else:
        # Python 3 bytes objects contain integer values in the range 0-255
        return bytes([a ^ b for a, b in zip(s, t)])


def xor2_strings(s, t) -> bytes:
    while (len(s) > len(t)):
        t = t + t[:(len(s) - len(t))]

    if (len(s) < len(t)):
        t = t[:len(s)]
        return xor_strings(s, t)
    else:
        return xor_strings(s, t)


def encrypt_AES_Key(aesKey, Ke):
    c = xor2_strings(aesKey, Ke)
    return c


def generate_hmac(Km, c):
    t = hmac.new(Km, c, hashlib.sha256)
    return t


def verify_hmac_tags(tag1, tag2):
    if (tag1.digest() == tag2):
        return True
    else:
        return False


def encrypt_ecies(aesKey, publicKeyOfReceiver):
    r, V = generate_ephemeral_keyPair()
    sharedSecret = generate_shared_secret(r, publicKeyOfReceiver)
    salt = get_random_bytes(16)
    Ke, Km = key_derivation_func(sharedSecret, salt)
    c = encrypt_AES_Key(aesKey, Ke)
    t = generate_hmac(Km, c)
    return (V, c, t, salt)


def decrypt_ecies(V, c, t, salt, privKeyOfReceiver):
    sharedSecret = generate_shared_secret(privKeyOfReceiver, V)
    Ke, Km = key_derivation_func(sharedSecret, salt)
    aesKey = xor2_strings(c, Ke)
    td = generate_hmac(Km, c)
    if (verify_hmac_tags(td, t)):
        return aesKey
    else:
        return f'Something went wrong with the auth verify!'
