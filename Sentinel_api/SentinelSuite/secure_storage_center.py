import base64
import os
import random
from datetime import datetime, timedelta

from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

from Sentinel_api.SentinelSuite.IAM_DB import db
from Sentinel_api.app import app
from Sentinel_api.app.models import SentinelKMS, File

import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException

api_instance = cloudmersive_virus_api_client.ScanApi()
api_instance.api_client.configuration.api_key['Apikey'] = '5254ef97-1f7b-449f-a8e7-74bf16c3523d'

def cloudmersivescan_api(file, filename):
    # uncomment when in production
    try:
        file_content = file.read()
        file_name = str(random.randint(100000,111111)) + "." + filename.split(".")[1]
        print(os.getcwd())
        saved_file_path = os.path.join(os.getcwd(), secure_filename(file_name))
        with open(saved_file_path, 'wb') as f:
            f.write(file_content)
        # Scan a file for viruses
        api_response = api_instance.scan_file(saved_file_path)
        response_data = api_response
        # pprint(api_response)
        clean_result = response_data.clean_result
        print(clean_result)
        if clean_result:
            os.remove(saved_file_path)
            return file_content
        else:
            os.remove(saved_file_path)
            return False
    except ApiException as e:
        print("Exception when calling ScanApi->scan_file: %s\n" % e)
        return False


def cloudmersivescan(file, filename):
    # uncomment when in production
    try:
        file_content = file.read()
        file_name = str(random.randint(100000,111111)) + "." + filename.split(".")[1]
        print(os.getcwd())
        saved_file_path = os.path.join(os.getcwd(), "../SentinelSuite/DMZ", secure_filename(file_name))
        with open(saved_file_path, 'wb') as f:
            f.write(file_content)
        # Scan a file for viruses
        api_response = api_instance.scan_file(saved_file_path)
        response_data = api_response
        # pprint(api_response)
        clean_result = response_data.clean_result
        print(clean_result)
        if clean_result:
            os.remove(saved_file_path)
            return file_content
        else:
            os.remove(saved_file_path)
            return False
    except ApiException as e:
        print("Exception when calling ScanApi->scan_file: %s\n" % e)
        return False

def generate_fernet_key():
    return Fernet.generate_key()

def encrypt_with_key(key, data):
    hex_key = bytes.fromhex(key[2:])
    cipher_suite = Fernet(hex_key)
    return cipher_suite.encrypt(data)

def decrypt_with_key(key, encrypted_data):
    hex_key = bytes.fromhex(key[2:])
    cipher_suite = Fernet(hex_key)
    return cipher_suite.decrypt(encrypted_data)

def rotate_encrypt(key, data):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data)


def encrypt_file(file):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_content = cipher_suite.encrypt(file.read())
    return key, encrypted_content

def decrypt_file(key, encrypted_content):
    cipher_suite = Fernet(key)
    decrypted_content = cipher_suite.decrypt(encrypted_content)
    return decrypted_content

# Function to rotate keys and re-encrypt files
def rotate_keys_and_reencrypt(interval):
    with app.app_context():
        # Get all SentinelKMS entries
        sentinel_kms_entries = SentinelKMS.query.all()

        # for every key in the sentinel kms
        # i will get all files encrypted with that key
        # then i will decrypt all files with existing key
        # before reecnrypting with new key
        # then set that specific bucket key value to new key and set new date of rotation
        for sentinel_kms in sentinel_kms_entries:
            # Rotate the key every 30 days
            if datetime.now() - sentinel_kms.last_date_of_rotation > timedelta(days=interval):
                new_key = generate_fernet_key()
                encrypted_files = File.query.filter_by(bucket_id=sentinel_kms.bucket_id).all()

                for encrypted_file in encrypted_files:
                    decrypted_content = decrypt_with_key(sentinel_kms.encryption_key, encrypted_file.encrypted_content)
                    encrypted_file.encrypted_content = rotate_encrypt(new_key, decrypted_content)

                sentinel_kms.encryption_key = new_key
                sentinel_kms.last_date_of_rotation = datetime.now()

        db.session.commit()


