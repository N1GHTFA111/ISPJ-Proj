import secrets
import uuid
import datetime
from datetime import timedelta

import flask_login
from flask_login import UserMixin
from sqlalchemy.orm import relationship

from Sentinel_api.app import login_manager

from Sentinel_api.SentinelSuite.IAM_DB import db

# configure account lockout policy
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 3  # 3 min

class SentinelIAMUserModel(db.Model, UserMixin):
    id = db.Column(db.String(100), primary_key=True, default="IAM"+str(uuid.uuid4()), unique=True)
    app_api_key = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role_name = db.Column(db.String(100), db.ForeignKey('roles.rolename'))

    forget_password_token = db.Column(db.String(200), server_default='None')
    otp_token = db.Column(db.String(200), server_default='None')
    lock_status = db.Column(db.String(80), server_default='Unlocked')
    failed_login_attempts = db.Column(db.Integer, server_default='0')
    locked_time = db.Column(db.DateTime, server_default=None)

    enable_2fa_email = db.Column(db.String(80), server_default='Not Enabled')

    # used for rmb me token
    alternative_token = db.Column(db.String(200), nullable=False, server_default='None')

    def __init__(self,  app_api_key, username, email, phone, password, role):
        self.id = "IAM"+str(uuid.uuid4())
        self.app_api_key = app_api_key
        self.username = username
        self.email = email
        self.phone = phone
        self.password = password
        self.role_name = role


    def __repr__(self):
        return f'<ClientUser {self.username}>'

    def get_id(self):
        return self.id

    def get_username(self):
        return self.username

    def get_email(self):
        return self.email

    def get_phone(self):
        return self.phone

    def get_password(self):
        return self.password

    def get_role(self):
        return self.role_name

    def get_forget_password_token(self):
        return self.forget_password_token

    def get_otp_token(self):
        return self.otp_token

    def get_enable_2fa_email(self):
        return self.enable_2fa_email

    def get_alternative_token(self):
        return self.alternative_token

    def set_username(self, name):
        self.username = name

    def set_role(self, role):
        self.role_name = role

    def set_email(self, email):
        self.email = email

    def set_phone(self, phone):
        self.phone = phone

    def set_password(self, password):
        self.password = password

    def set_forget_password_token(self, value):
        self.forget_password_token = value

    def set_otp_token(self, value):
        self.otp_token = value

    def set_failed_login_attempts(self, attempts):
        self.failed_login_attempts = attempts

    def get_failed_login_attempts(self):
        return self.failed_login_attempts

    def failed_login_increment(self):
        login_attempts = self.get_failed_login_attempts() + 1
        self.set_failed_login_attempts(login_attempts)
        if self.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            self.lock_status = "Locked"
            self.locked_time = datetime.datetime.now()

    def check_locked_time_done(self):
        if self.locked_time is None:
            return True
        elif self.locked_time is not None and self.locked_time + timedelta(
                minutes=LOCKOUT_DURATION) <= datetime.datetime.now():
            self.reset_account_after_lockdown()
            return True
        else:
            return False

    def reset_account_after_lockdown(self):
        self.lock_status = "Unlocked"
        self.locked_time = None

    def reset_failed_login_count(self):
        self.failed_login_attempts = 0
        self.lock_status = "Unlocked"

    def isLocked(self):
        if self.lock_status == "Locked":
            return True
        else:
            return False

    def add_new_column(self):
        self.locked_time = None
        self.lock_status = "Unlocked"
        self.failed_login_attempts = 0

    def set_enable_2fa_email(self, enabled):
        self.enable_2fa_email = enabled

    def set_alternative_token(self, token):
        self.alternative_token = token



# reserve this for the bank website
# 4 roles
# Public user (clearance 1)
# employee (clearance 2)
# manager has limited access to confidential data (clearance 3)
# Senior Management (clearance 4)
class RoleModel(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.String(100), primary_key=True)
    rolename = db.Column(db.String(100), unique=True, nullable=False)
    # can change employee details
    #level_of_access = db.Column(db.String(100), unique=True, nullable=False)
    executive_permission = db.Column(db.String(80), default='Unauthorized')
    manager_permission = db.Column(db.String(80), default='Unauthorized')
    IT_permission = db.Column(db.String(80), default='Unauthorized')
    employee_permission = db.Column(db.String(80), default='Unauthorized')
    user_permission = db.Column(db.String(80), default='Unauthorized')


    def __init__(self, rolename):
        self.id = "ROLE"+str(uuid.uuid4())
        self.rolename = rolename


    def get_id(self):
        return self.id

    def get_rolename(self):
        return self.rolename

    def get_executive_permission(self):
        return self.executive_permission

    def get_manager_permission(self):
        return self.manager_permission

    def get_IT_permission(self):
        return self.IT_permission

    def get_employee_permission(self):
        return self.employee_permission

    def get_user_permission(self):
        return self.user_permission




    def set_id(self, value):
        self.id = value

    def set_rolename(self, value):
        self.rolename = value

    def set_executive_permission(self, value):
        self.executive_permission = value

    def set_manager_permission(self, value):
        self.manager_permission = value

    def set_IT_permission(self, value):
        self.IT_permission = value

    def set_employee_permission(self, value):
        self.employee_permission = value

    def set_user_permission(self, value):
        self.user_permission = value




class LogsModel(db.Model):
    log_id = db.Column(db.String(100), primary_key=True)
    app_api_key = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.String(120))
    classification = db.Column(db.String(120), nullable=False)
    priority = db.Column(db.String(200), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    target = db.Column(db.String(500), nullable=False)
    details = db.Column(db.String(200), nullable=False)
    source_ip = db.Column(db.String(160), nullable=False)

    def get_log_id(self):
        return self.log_id

    def get_user_id(self):
        return self.user_id

    def get_classification(self):
        return self.classification

    def get_priority(self):
        return self.priority

    def get_time(self):
        return self.time

    def get_target(self):
        return self.target

    def get_details(self):
        return self.details

    def get_source_ip(self):
        return self.source_ip

class EVIRECModel(db.Model):
    evirec_id = db.Column(db.String(100), primary_key=True)
    log_id = db.Column(db.String(120), db.ForeignKey('logs_model.log_id'))
    path_name = db.Column(db.String(120), nullable=False)
    user_who_added = db.Column(db.String(100), db.ForeignKey('sentinel_user_model.id'), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    time_updated = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(200), nullable=False, default='None')

    # now to access associated log, just use evirec.log.get_user_id() or whatever function
    log = relationship('LogsModel', backref='evirec')
    user = relationship('SentinelUserModel', backref='evirec_user')

    def __init__(self, logid, pathname, description):
        self.evirec_id = "EVIREC"+str(uuid.uuid4())
        self.log_id = logid
        self.path_name = pathname
        self.user_who_added = flask_login.current_user.get_id()
        self.time = datetime.datetime.now()
        self.time_updated = datetime.datetime.now()
        self.description = description

    def get_log(self):
        return self.log

    def get_evirec_id(self):
        return self.evirec_id

    def set_evirec_id(self, evirec_id):
        self.evirec_id = evirec_id

    def get_log_id(self):
        return self.log_id

    def set_log_id(self, log_id):
        self.log_id = log_id

    def get_path_name(self):
        return self.path_name

    def set_path_name(self, path_name):
        self.path_name = path_name

    def get_user_who_added(self):
        return self.user_who_added

    def set_user_who_added(self, value):
        self.user_who_added = value

    def get_time(self):
        return self.time

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_time_updated(self):
        return self.time_updated

    def set_time_updated(self, value):
        self.time_updated = value

class SentinelUserModel(db.Model, UserMixin):
    id = db.Column(db.String(200), primary_key=True, default="SentinelUser"+str(uuid.uuid4()), unique=True)
    api_key = db.Column(db.String(100), nullable=False, default="INVALID")
    email = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role_name = db.Column(db.String(100), db.ForeignKey('sentinel_roles.rolename'))

    forget_password_token = db.Column(db.String(200), server_default='None')
    otp_token = db.Column(db.String(200), server_default='None')
    lock_status = db.Column(db.String(80), server_default='Unlocked')
    failed_login_attempts = db.Column(db.Integer, server_default='0')
    locked_time = db.Column(db.DateTime, server_default=None)

    enable_2fa_email = db.Column(db.String(80), server_default='Not Enabled')

    # used for rmb me token
    alternative_token = db.Column(db.String(200), nullable=False, server_default='None')

    def __init__(self, username, email, phone, password, role):
        self.id = "SentinelUser"+str(uuid.uuid4())
        self.username = username
        self.email = email
        self.phone = phone
        self.password = password
        self.role_name = role

        if self.role_name == "DEVELOPER":
            self.api_key = secrets.token_urlsafe(32)
        else:
            self.api_key = "INVALID"


    def __repr__(self):
        return f'<ClientUser {self.username}>'

    def get_api_key(self):
        return self.api_key

    def get_id(self):
        return self.id

    def get_username(self):
        return self.username

    def get_email(self):
        return self.email

    def get_phone(self):
        return self.phone

    def get_password(self):
        return self.password

    def get_role(self):
        return self.role_name

    def get_forget_password_token(self):
        return self.forget_password_token

    def get_otp_token(self):
        return self.otp_token

    def get_enable_2fa_email(self):
        return self.enable_2fa_email

    def get_alternative_token(self):
        return self.alternative_token

    def set_username(self, name):
        self.username = name

    def set_role(self, role):
        self.role_name = role

    def set_email(self, email):
        self.email = email

    def set_phone(self, phone):
        self.phone = phone

    def set_password(self, password):
        self.password = password

    def set_forget_password_token(self, value):
        self.forget_password_token = value

    def set_otp_token(self, value):
        self.otp_token = value

    def set_failed_login_attempts(self, attempts):
        self.failed_login_attempts = attempts

    def get_failed_login_attempts(self):
        return self.failed_login_attempts

    def failed_login_increment(self):
        login_attempts = self.get_failed_login_attempts() + 1
        self.set_failed_login_attempts(login_attempts)
        if self.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            self.lock_status = "Locked"
            self.locked_time = datetime.datetime.now()

    def check_locked_time_done(self):
        if self.locked_time is None:
            return True
        elif self.locked_time is not None and self.locked_time + timedelta(
                minutes=LOCKOUT_DURATION) <= datetime.datetime.now():
            self.reset_account_after_lockdown()
            return True
        else:
            return False

    def reset_account_after_lockdown(self):
        self.lock_status = "Unlocked"
        self.locked_time = None

    def reset_failed_login_count(self):
        self.failed_login_attempts = 0
        self.lock_status = "Unlocked"

    def isLocked(self):
        if self.lock_status == "Locked":
            return True
        else:
            return False

    def add_new_column(self):
        self.locked_time = None
        self.lock_status = "Unlocked"
        self.failed_login_attempts = 0

    def set_enable_2fa_email(self, enabled):
        self.enable_2fa_email = enabled

    def set_alternative_token(self, token):
        self.alternative_token = token

class SentinelIAMAccessUsers(db.Model):
    id = db.Column(db.String(200), primary_key=True, unique=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)

# reserve this for the Sentinel website
class SentinelRoleModel(db.Model):
    __tablename__ = 'sentinel_roles'
    id = db.Column(db.String(100), primary_key=True)
    rolename = db.Column(db.String(100), unique=True, nullable=False)
    # control backend of sentinel
    superadmin_permission = db.Column(db.String(80), default='Unauthorized')
    # can use services and api key
    developer_permission = db.Column(db.String(80), default='Unauthorized')
    # employee can only store files and send secure email, but cannot use api key
    employee_permission = db.Column(db.String(80), default='Unauthorized')


    def __init__(self, rolename):
        self.id = "STNL_ROLE"+str(uuid.uuid4())
        self.rolename = rolename

    def get_id(self):
        return self.id

    def get_rolename(self):
        return self.rolename

    def get_superadmin_permission(self):
        return self.superadmin_permission

    def set_superadmin_permission(self, value):
        self.superadmin_permission = value

    def get_employee_permission(self):
        return self.employee_permission

    def set_employee_permission(self, value):
        self.employee_permission = value


    def get_developer_permission(self):
        return self.developer_permission

    def set_developer_permission(self, value):
        self.developer_permission = value



    def set_id(self, value):
        self.id = value

    def set_rolename(self, value):
        self.rolename = value


class SentinelKMS(db.Model):
    id = db.Column(db.String(200), primary_key=True, default="KEY"+str(uuid.uuid4()), unique=True)
    last_date_of_rotation = db.Column(db.DateTime, default=datetime.datetime.now())
    encryption_key = db.Column(db.String(300), nullable=False)
    bucket_id = db.Column(db.String(200), nullable=False)

    def __init__(self, key, bucket_id):
        self.id = "KEY"+str(uuid.uuid4())
        self.encryption_key = key
        self.last_date_of_rotation = datetime.datetime.now()
        self.bucket_id = bucket_id

    def get_key(self):
        return self.encryption_key

class LifecyclePolicy(db.Model):
    __tablename__ = 'lifecycle_policy'
    id = db.Column(db.String(200), primary_key=True)
    days_to_archive = db.Column(db.Integer)
    days_to_permanent_deletion = db.Column(db.Integer)
    # Define other policy attributes as needed
    # Define a backref to refer back to the associated Bucket

    def __init__(self, days_to_archive, days_to_permanent_deletion):
        self.id = "LifePol"+str(uuid.uuid4())
        self.days_to_archive = days_to_archive
        self.days_to_permanent_deletion = days_to_permanent_deletion

    def get_days_to_archive(self):
        return self.days_to_archive

    def get_days_to_permanent_deletion(self):
        return self.days_to_permanent_deletion

class BucketAccess(db.Model):
    __tablename__ = 'bucket_access'
    id = db.Column(db.String(200), primary_key=True)
    bucket_id = db.Column(db.String(200), db.ForeignKey('bucket.id', ondelete='CASCADE'))
    email = db.Column(db.String(100))

    def __init__(self, bucket_id, email):
        self.id = "ACL" + str(uuid.uuid4())
        self.bucket_id = bucket_id
        self.email = email

    def get_email(self):
        return self.email

# this bucket is like google drive for employees to share stuff
# there will be another layer, 3 immutable buckets called public data, private data and confidential data
# using machine learning to detect
class Bucket(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    name = db.Column(db.String(100), unique=True)
    user_id = db.Column(db.String(200), db.ForeignKey('sentinel_user_model.id'))
    lifecycle_policy_id = db.Column(db.String(200), db.ForeignKey('lifecycle_policy.id', ondelete='CASCADE'), unique=True, nullable=True)
    sentinel_kms_id = db.Column(db.String(200), db.ForeignKey('sentinel_kms.id'))
    availability = db.Column(db.String(200), default="Private")

    # if availability is public, they can add email to share to specific accounts the files


    # Define relationships and other bucket attributes
    files = db.relationship('File', backref='parent_bucket', lazy='dynamic')
    lifecycle_policy = db.relationship('LifecyclePolicy', uselist=False, backref='bucket', cascade='all, delete', foreign_keys=[lifecycle_policy_id],)
    sentinel_kms = db.relationship('SentinelKMS', cascade='all, delete', backref='bucket_attached', uselist=False, foreign_keys=[sentinel_kms_id], single_parent=True)
    access_list = db.relationship('BucketAccess', backref='access_bucket', lazy='dynamic', cascade='all, delete-orphan')

    def __init__(self, name, availability, lifecycle_policy_id, user_id):
        self.id = "Bucket"+str(uuid.uuid4())
        self.name = name
        self.availability = availability
        self.user_id = user_id
        self.lifecycle_policy_id = lifecycle_policy_id

    def set_sentinel_kms_id(self, value):
        self.sentinel_kms_id = value

    def get_name(self):
        return self.name

    def get_availability(self):
        return self.availability

    def get_lifecycle_policy(self):
        return self.lifecycle_policy

class BackupBucket(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    bucket_id = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    user_id = db.Column(db.String(200))
    lifecycle_policy_id = db.Column(db.String(200), nullable=True)
    sentinel_kms_id = db.Column(db.String(200))
    availability = db.Column(db.String(200), default="Private")
    backup_date = db.Column(db.DateTime, default=None)

    # def __init__(self, bucket_id, name, availability, lifecycle_policy_id, user_id):
    #     self.id = "BackupBucket"+str(uuid.uuid4())
    #     self.bucket_id = bucket_id
    #     self.name = name
    #     self.availability = availability
    #     self.user_id = user_id
    #     self.lifecycle_policy_id = lifecycle_policy_id
    #     self.backup_date = datetime.datetime.now()

    def set_sentinel_kms_id(self, value):
        self.sentinel_kms_id = value

    def get_name(self):
        return self.name

    def get_availability(self):
        return self.availability

class BackupFile(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    backup_bucket_id = db.Column(db.String(200))
    file_id = db.Column(db.String(200))
    name = db.Column(db.String(255))
    path = db.Column(db.String(255))
    encrypted_content = db.Column(db.LargeBinary)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.now())
    bucket_id = db.Column(db.String(200)) # id of the backup bucket
    user_id = db.Column(db.String(200))
    # difference is temp deleted means file is visible in table but not deleted and can be restored
    temp_deleted = db.Column(db.String(200), default="Not Deleted")
    restore_time_limit = time_to_delete = db.Column(db.DateTime, default=None)
    # file will last for archival period but cannot be retrieved anymore
    permanently_deleted = db.Column(db.String(200), default="Not Permanently Deleted")
    time_to_delete = db.Column(db.DateTime, default=None)

    # def __init__(self, file_id, filename, content, bucket_id, user_id):
    #     self.id = "BackupFile"+str(uuid.uuid4())
    #     self.file_id = file_id
    #     self.name = filename
    #     self.encrypted_content = content
    #     self.bucket_id = bucket_id
    #     self.user_id = user_id

class BackupSentinelKMS(db.Model):
    id = db.Column(db.String(200), primary_key=True, default="KEY"+str(uuid.uuid4()), unique=True)
    backup_bucket_id = db.Column(db.String(200))
    kms_id = db.Column(db.String(200))
    last_date_of_rotation = db.Column(db.DateTime, default=datetime.datetime.now())
    encryption_key = db.Column(db.String(300), nullable=False)
    bucket_id = db.Column(db.String(200), nullable=False)

    def __init__(self, backup_bucket_id, kms_id, last_date_of_rotation, key, bucket_id):
        self.id = "BackupKEY"+str(uuid.uuid4())
        self.backup_bucket_id=backup_bucket_id
        self.kms_id = kms_id
        self.encryption_key = key
        self.last_date_of_rotation = last_date_of_rotation
        self.bucket_id = bucket_id

    def get_key(self):
        return self.encryption_key

class BackupLifecyclePolicy(db.Model):
    __tablename__ = 'lifecycle_policy_backup'
    id = db.Column(db.String(200), primary_key=True)
    backup_bucket_id = db.Column(db.String(200))
    lifecycle_id = db.Column(db.String(200))
    days_to_archive = db.Column(db.Integer)
    days_to_permanent_deletion = db.Column(db.Integer)
    # Define other policy attributes as needed
    # Define a backref to refer back to the associated Bucket

    def __init__(self, backup_bucket_id, life_id, days_to_archive, days_to_permanent_deletion):
        self.id = "BackupLifePol"+str(uuid.uuid4())
        self.backup_bucket_id = backup_bucket_id
        self.lifecycle_id = life_id
        self.days_to_archive = days_to_archive
        self.days_to_permanent_deletion = days_to_permanent_deletion

    def get_days_to_archive(self):
        return self.days_to_archive

    def get_days_to_permanent_deletion(self):
        return self.days_to_permanent_deletion

class BackupBucketAccess(db.Model):
    __tablename__ = 'bucket_access_backup'
    id = db.Column(db.String(200), primary_key=True)
    backup_bucket_id = db.Column(db.String(200))
    acl_id = db.Column(db.String(200))
    bucket_id = db.Column(db.String(200))
    email = db.Column(db.String(100))

    def __init__(self, backup_bucket_id, acl_id, bucket_id, email):
        self.id = "BackupACL"+str(uuid.uuid4())
        self.backup_bucket_id = backup_bucket_id
        self.acl_id = acl_id
        self.bucket_id = bucket_id
        self.email = email

    def get_email(self):
        return self.email



class File(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    name = db.Column(db.String(255))
    path = db.Column(db.String(255))
    encrypted_content = db.Column(db.LargeBinary)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.now())
    bucket_id = db.Column(db.String(200), db.ForeignKey('bucket.id'))
    user_id = db.Column(db.String(200), db.ForeignKey('sentinel_user_model.id'))
    # difference is temp deleted means file is visible in table but not deleted and can be restored
    temp_deleted = db.Column(db.String(200), default="Not Deleted")
    restore_time_limit = time_to_delete = db.Column(db.DateTime, default=None)
    # file will last for archival period but cannot be retrieved anymore
    permanently_deleted = db.Column(db.String(200), default="Not Permanently Deleted")
    time_to_delete = db.Column(db.DateTime, default=None)

    bucket = relationship('Bucket', backref='bucket_files')

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

class EllipticVerifier(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    signature = db.Column(db.String(500), nullable=False)
    privateKey = db.Column(db.String(1200), nullable=False)
    hash_val = db.Column(db.String(300), nullable=False)

    def __init__(self, signature, privateKey, hash_val):
        self.id = "VERI"+str(uuid.uuid4())
        self.signature = signature
        self.privateKey = privateKey
        self.hash_val = hash_val

    def get_signature(self):
        return self.signature

class FirewallBlockList(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    block_ip = db.Column(db.String(200), nullable=False)
    time_of_add = db.Column(db.DateTime, default=None)
    time_of_update = db.Column(db.DateTime, default=None)

    def __init__(self, ip):
        self.id = "BlockRule"+str(uuid.uuid4())
        self.block_ip = ip
        self.time_of_add = datetime.datetime.now()
        self.time_of_update = datetime.datetime.now()

    def update_ip(self, ip):
        self.block_ip = ip
        self.time_of_update = datetime.datetime.now()

class APICommunicationSecurer(db.Model):
    id = db.Column(db.String(200), primary_key=True)
    key = db.Column(db.String(300), nullable=False)
    nonce = db.Column(db.String(300), nullable=False)
    aad = db.Column(db.String(300), nullable=False)


    def __init__(self, key, nonce, aad):
        self.id = "COMMS"+str(uuid.uuid4())
        self.key = key
        self.nonce = nonce
        self.aad = aad

    def get_signature(self):
        return self.signature

@login_manager.user_loader
def load_user_sentinel(user_id):
    # Assuming you have a way to determine the user type based on the user_id
    # You might use a prefix or some other mechanism
    return SentinelUserModel.query.get(user_id)

