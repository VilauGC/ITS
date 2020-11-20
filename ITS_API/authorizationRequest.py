"""
Authorization Request sent by ITS after receiving EC from EA after a successful Enrolment Request

"""
from functions import (generateKeyPair_secp256r1, generate_hmac)
from Cryptodome.Random import get_random_bytes
import pickle

def make_authorization_request():
    # Pasul 1
    # Se creeaza o pereche de chei care se va crea pentru fiecare authorization request
    
    (r_ef, V_ef) = generateKeyPair_secp256r1()
    
    # Pasul 2 Optional in cazul in care avem nevoie de privacy pentru ITS-ul nostru 

    (r_enc, V_enc) = generateKeyPair_secp256r1()

    # Pasul 3 Se genereaza un hmac-key (secret) de 32 bytes

    hmac_key = get_random_bytes(32)
    
    # Pasul 4 Se creeza un tag folosing functia de hash HMAC_SHA256 de cheile publice ef si enc serializate si concatenate

    # 4.1 Serializez cheile publice V_ef si V_enc

    V_ef_bytes = pickle.dumps(V_ef)
    V_enc_bytes = pickle.dumps(V_enc)
    
    # 4.2 Concatenez cele doua chei serializate

    V_concat = V_ef_bytes + V_enc_bytes

    # 4.3 Apelez functia de hash pentru a obtine un tag de 32 de bytes

    tag = generate_hmac(hmac_key,V_concat)
    tag = tag.digest()
    
    # 4.4 Trunchiez tag-ul la 16 bytes(128 bits to the leftmost)
    keyTag = tag[16:]


    