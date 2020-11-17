from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def encrypt_AESCCM(message):
    header = b'header'
    aesKey = get_random_bytes(16)
    nonce = get_random_bytes(12)
    cipher = AES.new(aesKey, AES.MODE_CCM, nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    data = {"AES-Key": aesKey, "ciphertext": ciphertext,
            "auth-tag": tag, "nonce": nonce, "header": header}
    return data


def encrypt_AESCCM_withKey(message, key):
    header = b'header'
    aesKey = get_random_bytes(16)
    nonce = get_random_bytes(12)
    cipher = AES.new(aesKey, AES.MODE_CCM, nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    data = {"AES-Key": aesKey, "ciphertext": ciphertext,
            "auth-tag": tag, "nonce": nonce, "header": header}
    return data


def decrypt_AESCCM(key, nonce, ciphertext, tag, header):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
