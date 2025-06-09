import json
import os
import secrets
import string
from Sentinel_api.SentinelSuite.Sentinel_Sha1024 import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Sentinel_api.app import app
from Sentinel_api.SentinelSuite.IAM_DB import db
from Sentinel_api.app.models import APICommunicationSecurer
# db will store the key, nonce, aad

# data = {
#     "username": "Tom",
#     "password": "Password1"
# }
#
# aad = hashing_sha1024(''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(256))).encode('utf-8')

def encrypt_transmission(data):
    with app.app_context():
        aad = hashing_sha1024(''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(256))).encode('utf-8')
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        json_data = json.dumps(data).encode('utf-8')
        ct = aesgcm.encrypt(nonce, json_data, aad)


        new_comms_entry = APICommunicationSecurer(key=key, nonce=nonce, aad=aad.decode('utf-8'))
        db.session.add(new_comms_entry)
        db.session.commit()

        return ct, aad

def decrypt_transmission(encrypted_data, aad):
    # get comms entry via aad
    with app.app_context():
        aad = aad.decode('utf-8')
        comms_entry = APICommunicationSecurer.query.filter_by(aad=aad).first()
        key = bytes.fromhex(comms_entry.key[2:])
        print(key)
        nonce = bytes.fromhex(comms_entry.nonce[2:])
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, aad.encode())
        return json.loads(decrypted_data.decode('utf-8'))


# key, ciphertext, nonce, aad = encrypt(data, aad)
# print("Encrypted data:",ciphertext)
#
# decrypted_data = decrypt(key, ciphertext, nonce, aad)
# print("Decrypted data:", decrypted_data)
# print("Password:", decrypted_data['password'])