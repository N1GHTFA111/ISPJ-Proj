import datetime
import os
import secrets
import uuid

import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, g, abort, \
    send_from_directory
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import relationship

bank_app = Flask(__name__, template_folder='../templates_bank', static_folder='../static')


# load environ vars
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config', '.env_client'))
bank_app.config['TEMPLATES_AUTO_RELOAD'] = True
bank_app.config['SESSION_COOKIE_NAME'] = 'bank_client_session'

app_secret_key = "SENTINELSUITE"
bank_app.config['SECRET_KEY'] = app_secret_key

# Configure your app settings, database, and other configurations here
bank_app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/bankdb'

# Initialize common database
db_bank = SQLAlchemy(bank_app)
login_manager = LoginManager(bank_app)
migrate = Migrate(bank_app, db_bank, render_as_batch=True)
csrf = CSRFProtect(bank_app)
csrf.init_app(bank_app)

BANK_API_BASE_URL = 'https://127.0.0.1:6500'


api_key = "SENTINEL_SUITE_BETA"



class UserModel(db_bank.Model, UserMixin):
    id = db_bank.Column(db_bank.String(100), primary_key=True, default="IAM" + str(uuid.uuid4()), unique=True)
    email = db_bank.Column(db_bank.String(80), unique=True, nullable=False)
    username = db_bank.Column(db_bank.String(100), unique=True, nullable=False)
    phone = db_bank.Column(db_bank.String(120), )
    password = db_bank.Column(db_bank.String(200), unique=True, nullable=False)
    role_name = db_bank.Column(db_bank.String(100), nullable=False)
    account = db_bank.relationship('AccountModel', backref='user_model', uselist=False)

    def __init__(self, id, email, username,role_name, password, phone):
        self.id = id
        self.email = email
        self.username = username
        self.phone = phone
        self.role_name = role_name
        self.password = password

        if role_name == "USER":
            self.account = AccountModel(user=self)
        else:
            self.account = None

    def get_id(self):
        return self.id

    def get_email(self):
        return self.email

    def get_username(self):
        return self.username

    def get_role(self):
        return self.role_name

    def set_email(self, email):
        self.email = email

    def set_username(self, username):
        self.username = username

    def set_role(self, role):
        self.role_name = role

    def get_password(self):
        return self.password

    def set_password(self, password):
        self.password = password

    def set_phone(self, phone):
        self.phone = phone

    def get_phone(self):
        return self.phone



# for the bank
class AccountModel(db_bank.Model):
    account_id = db_bank.Column(db_bank.String(200), primary_key=True)
    user_id = db_bank.Column(db_bank.String(100), db_bank.ForeignKey('user_model.id'), nullable=False)
    balance = db_bank.Column(db_bank.Float, nullable=False)


    def __init__(self, user):
        self.account_id = "ACCT"+str(uuid.uuid4())
        self.user_id = user.id
        self.balance = 0.0

    def get_id(self):
        return self.account_id

    def set_id(self, value):
        self.account_id = value

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, value):
        self.user_id = value

    def get_balance(self):
        return self.balance

    def set_balance(self, value):
        self.balance = value

class TransactionModel(db_bank.Model):
    transaction_id = db_bank.Column(db_bank.String(200), primary_key=True)
    src_account_id = db_bank.Column(db_bank.String(200), nullable=False)
    src_username =  db_bank.Column(db_bank.String(200), primary_key=True)
    dst_account_id = db_bank.Column(db_bank.String(200),  nullable=False)
    dst_username =  db_bank.Column(db_bank.String(200), primary_key=True)
    time = db_bank.Column(db_bank.DateTime, nullable=False)
    transaction_amount = db_bank.Column(db_bank.Float, nullable=False)
    transaction_type = db_bank.Column(db_bank.String(200), nullable=False)
    ethereum_hash = db_bank.Column(db_bank.String(300))
    combined_hash = db_bank.Column(db_bank.String(300))

    def __init__(self, transact_id, src_account_id, dst_account_id, time, transaction_amount, transaction_type, src_username, dst_username):
        self.transaction_id = transact_id
        self.src_account_id = src_account_id
        self.dst_account_id = dst_account_id
        self.time = time
        self.transaction_amount = transaction_amount
        self.transaction_type = transaction_type
        self.src_username = src_username
        self.dst_username = dst_username

    def get_time(self):
        return self.time

    def get_amount(self):
        return self.transaction_amount

    def get_type(self):
        return self.transaction_type

    def get_src_username(self):
        # Access the username via the account relationship
        return self.src_username

    def get_dst_username(self):
        return self.dst_username

    def set_ethereum_hash(self, hash):
        self.ethereum_hash = hash

    def get_ethereum_hash(self):
        return self.ethereum_hash

    def set_combined_hash(self, hash):
        self.combined_hash = hash

    def get_combined_hash(self):
        return self.combined_hash

class SentinelKMSAPI(db_bank.Model):
    __tablename__ = 'sentinel_kms_api'
    id = db_bank.Column(db_bank.String(200), primary_key=True, default="KEYAPI"+str(uuid.uuid4()), unique=True)
    last_date_of_rotation = db_bank.Column(db_bank.DateTime, default=datetime.datetime.now())
    encryption_key = db_bank.Column(db_bank.String(300), nullable=False)
    bucket_id = db_bank.Column(db_bank.String(200), nullable=False)

    def __init__(self, key, bucket_id):
        self.id = "KEYAPI" + str(uuid.uuid4())
        self.encryption_key = key
        self.last_date_of_rotation = datetime.datetime.now()
        self.bucket_id = bucket_id

    def get_key(self):
        return self.encryption_key

class LifecyclePolicyAPI(db_bank.Model):
    __tablename__ = 'lifecycle_policy_api'
    id = db_bank.Column(db_bank.String(200), primary_key=True)
    days_to_archive = db_bank.Column(db_bank.Integer)
    days_to_permanent_deletion = db_bank.Column(db_bank.Integer)
    # Define other policy attributes as needed
    # Define a backref to refer back to the associated Bucket

    def __init__(self, days_to_archive, days_to_permanent_deletion):
        self.id = "LifePolAPI"+str(uuid.uuid4())
        self.days_to_archive = days_to_archive
        self.days_to_permanent_deletion = days_to_permanent_deletion

    def get_days_to_archive(self):
        return self.days_to_archive

    def get_days_to_permanent_deletion(self):
        return self.days_to_permanent_deletion


class BucketAPI(db_bank.Model):
    id = db_bank.Column(db_bank.String(200), primary_key=True)
    name = db_bank.Column(db_bank.String(100), unique=True)
    lifecycle_policy_id = db_bank.Column(db_bank.String(200), db_bank.ForeignKey('lifecycle_policy_api.id', ondelete='CASCADE'), unique=True, nullable=True)
    sentinel_kms_id = db_bank.Column(db_bank.String(200), db_bank.ForeignKey('sentinel_kms_api.id'))

    # if availability is public, they can add email to share to specific accounts the files
    # Define relationships and other bucket attributes
    files = db_bank.relationship('FileAPI', backref='parent_bucket_api', lazy='dynamic')
    lifecycle_policy = db_bank.relationship('LifecyclePolicyAPI', uselist=False, backref='bucket_api', cascade='all, delete', foreign_keys=[lifecycle_policy_id],)
    sentinel_kms = db_bank.relationship('SentinelKMSAPI', cascade='all, delete', backref='bucket_api_attached', uselist=False, foreign_keys=[sentinel_kms_id], single_parent=True)

    def __init__(self, name, lifecycle_policy_id):
        self.id = "BucketAPI"+str(uuid.uuid4())
        self.name = name
        self.lifecycle_policy_id = lifecycle_policy_id

    def set_sentinel_kms_id(self, value):
        self.sentinel_kms_id = value

    def get_name(self):
        return self.name

    def get_availability(self):
        return self.availability

    def get_lifecycle_policy(self):
        return self.lifecycle_policy

class FileAPI(db_bank.Model):
    id = db_bank.Column(db_bank.String(200), primary_key=True)
    name = db_bank.Column(db_bank.String(255))
    path = db_bank.Column(db_bank.String(255))
    encrypted_content = db_bank.Column(db_bank.LargeBinary)
    uploaded_at = db_bank.Column(db_bank.DateTime, default=datetime.datetime.now())
    bucket_id = db_bank.Column(db_bank.String(200), db_bank.ForeignKey('bucket_api.id'))
    user_id = db_bank.Column(db_bank.String(200), nullable=False)
    # difference is temp deleted means file is visible in table but not deleted and can be restored
    temp_deleted = db_bank.Column(db_bank.String(200), default="Not Deleted")
    restore_time_limit = time_to_delete = db_bank.Column(db_bank.DateTime, default=None)
    # file will last for archival period but cannot be retrieved anymore
    permanently_deleted = db_bank.Column(db_bank.String(200), default="Not Permanently Deleted")
    time_to_delete = db_bank.Column(db_bank.DateTime, default=None)

    bucket = relationship('BucketAPI', backref='bucket_api_files')

    def set_restore_time_limit(self, delete):
        self.restore_time_limit = delete

    def get_restore_time_limit(self):
        return self.restore_time_limit

    def set_temp_deleted(self, delete):
        self.temp_deleted = delete

    def set_permanently_deleted(self, delete):
        self.permanently_deleted = delete

    def set_time_to_delete(self, delete):
        self.time_to_delete = delete

    def get_temp_deleted(self):
        return self.temp_deleted

    def get_name(self):
        return self.name

    def get_time_of_upload(self):
        return self.uploaded_at

    def get_bucket(self):
        return self.bucket

    def get_id(self):
        return self.id


# Load user from user_id
@login_manager.user_loader
def load_user_bank(user_id):
    return UserModel.query.get(user_id)



with bank_app.app_context():
    bank_app.config['DEBUG'] = True
    db_bank.create_all()  # In case user table doesn't exists already. Else remove it.






from Bank_app.app.routes import blueprint_name

# jinja function to check required roles
def check_permission(user, required_role):
    current_user_role = user.get_role()
    data = {"role": current_user_role}
    headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
    response = requests.post(f'{BANK_API_BASE_URL}/api/get_role_permissions', json=data, verify=False,
                             headers=headers)
    permissions_dict = response.json().get('permissions')


    if required_role == "EXECUTIVE" and permissions_dict['executive_permission'] == "Authorized":
        return True
    elif required_role == "MANAGER" and permissions_dict['manager_permission'] == "Authorized":
        return True
    elif required_role == "IT" and permissions_dict['IT_permission'] == "Authorized":
        return True
    elif required_role == "EMPLOYEE" and permissions_dict['employee_permission'] == "Authorized":
        return True
    else:
        return False

def mask_acct_id(acct_id):
    unmasked_id = acct_id.split("-")[0]
    masked_length = len(acct_id) - len(unmasked_id)
    masked_string = unmasked_id + '*' * masked_length
    return masked_string

bank_app.jinja_env.globals.update(check_permission=check_permission)
bank_app.jinja_env.globals.update(mask_acct_id=mask_acct_id)

bank_app.register_blueprint(blueprint_name, url_prefix='/')

# user has access to public bucket
# employee has access to internal bucket
# manager and IT both have access to the confidential bucket
# Executive has access to the Restricted bucket
# need to generate these buckets first

if __name__ == "__main__":
    bank_app.run(debug=True, port=5000, ssl_context=('cert.pem', 'key.pem'))