import hashlib

from PyPDF2 import PdfReader
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Sentinel_api.app import app
from Sentinel_api.app.models import EllipticVerifier
from Sentinel_api.SentinelSuite.IAM_DB import db


# get the hash to sign
def get_hash_of_pdf(file):
    with open(file, 'rb') as pdf_file:
        pdf_reader = PdfReader(pdf_file)
        hash_obj = hashlib.sha512()

        for page in pdf_reader.pages:
            hash_obj.update(page.extract_text().encode('utf-8'))
        return hash_obj.hexdigest()

def sign_file(private_key, hash):
    hash = hash.encode('utf-8')
    signature = private_key.sign(
        hash,
        ec.ECDSA(hashes.SHA512())
    )
    return signature

def generate_elliptic_keys():
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )

    public_key = private_key.public_key()

    # return this to the user side
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {"private_key":private_key,
            "public_key": public_key,
            "serialised_public_key":serialized_public}


def generate_verifier(hash_val, private_key):

    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'testpassword')
    )

    hash_to_sign = hash_val
    signature_to_store = sign_file(private_key, hash_to_sign)

    with app.app_context():
        new_signature_verifier = EllipticVerifier(signature=signature_to_store, privateKey=serialized_private, hash_val=hash_val)
        db.session.add(new_signature_verifier)
        db.session.commit()

    return "Success"

def load_public_key(public_key):
    loaded_public_key = serialization.load_pem_public_key(
        public_key,
    )
    return loaded_public_key


def elliptic_verify(hash_val, serialised_public_key):
    public_key = load_public_key(serialised_public_key.encode('utf-8'))

    with app.app_context():
        signature_from_db_row = EllipticVerifier.query.filter_by(hash_val=hash_val).first()
        signature_from_db = signature_from_db_row.get_signature()
        signature_from_db = bytes.fromhex(signature_from_db.replace("\\x", ""))

        try:
            public_key.verify(signature_from_db, hash_val.encode(), ec.ECDSA(hashes.SHA512()))
            print("Valid signature")
            return True
        except Exception as e:
            print("Signature not valid:", e)
            return False


