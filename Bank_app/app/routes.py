import base64
import datetime
import hashlib
import html
import os
import pprint
import random
import secrets
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage
from functools import wraps
from io import BytesIO

import bcrypt
import flask_login
import web3.eth
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, g, abort, \
    send_from_directory, send_file
from flask_login import current_user, login_user, login_required, logout_user
from flask_wtf.csrf import generate_csrf, CSRFError
import pyotp
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import joinedload
from web3 import Web3, HTTPProvider
from werkzeug.exceptions import Forbidden
from werkzeug.utils import secure_filename

import Sentinel_api.app.routes
from Bank_app.app import bank_app, db_bank, UserModel, AccountModel, TransactionModel, BucketAPI, SentinelKMSAPI, \
    LifecyclePolicyAPI, FileAPI
from Bank_app.app.forms import CreateBankUserForm, CreateBankAdminForm, UpdateBankUserForm, transfer_form, \
    deposit_withdraw_form, UploadFileFormAPI, UpdateBankExecForm, VerifyFileForm
from Sentinel_api.SentinelSuite.WAF import get_block_list
from Sentinel_api.SentinelSuite.directory_traversal_ai import is_traversal
from Sentinel_api.SentinelSuite.elliptic_document_verifier import generate_elliptic_keys, get_hash_of_pdf, \
    generate_verifier, elliptic_verify
from Sentinel_api.SentinelSuite.secure_storage_center import generate_fernet_key, encrypt_with_key, decrypt_with_key, \
    rotate_encrypt
from Sentinel_api.SentinelSuite.streams import add_to_log
from Sentinel_api.SentinelSuite.xss_detect_final import is_xss
from Sentinel_api.SentinelSuite.Sentinel_API_security import *
from Sentinel_api.app.forms import *
from Sentinel_api.app.models import SentinelIAMUserModel
import requests

from flask import Blueprint, render_template
# modules to create pdf invoice
# basic functions
from borb.pdf.document.document import Document
from borb.pdf.page.page import Page

# build pdf
from borb.pdf import PDF

# layout
from borb.pdf.canvas.layout.page_layout.multi_column_layout import SingleColumnLayout
from decimal import Decimal

# add image
from borb.pdf.canvas.layout.image.image import Image

# building the invoice
from borb.pdf.canvas.layout.text.paragraph import Paragraph
from borb.pdf.canvas.layout.layout_element import Alignment
import random

# adding color to pdf
from borb.pdf.canvas.color.color import HexColor, X11Color

# build item table
from borb.pdf.canvas.layout.table.fixed_column_width_table import FixedColumnWidthTable as Table
from borb.pdf.canvas.layout.table.table import TableCell

# create outline
from borb.pdf.canvas.layout.annotation.link_annotation import DestinationType
from borb.pdf.trailer import document_info
# add metadata
from PyPDF2 import PdfReader, PdfWriter

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

blueprint_name = Blueprint('Bank_Routes', __name__)

BANK_API_BASE_URL = 'https://127.0.0.1:6500'

api_key = "SENTINEL_SUITE_BETA"

# configure limiter
limiter = Limiter(get_remote_address, app=bank_app)

# setup pyotp
totp = pyotp.TOTP(pyotp.random_base32(), interval=60)

totp_for_forget_password = pyotp.TOTP(pyotp.random_base32(), interval=60)


@blueprint_name.before_request
def before_request():
    if is_traversal(request.url):
        print("Detected")
        add_to_log(classification="PATH TRAVERSAL",
                   target_route=html.escape(request.url),
                   priority=2,
                   details=f"Unauthorised Path Traversal",
                   app_api_key=api_key,
                   user_id="None")
        return redirect(url_for('Bank_Routes.authenticated_user'))
    else:
        with bank_app.app_context():
            blocked_ips = get_block_list()
            if request.remote_addr in blocked_ips:
                print("Access Denied")
                add_to_log(classification="JOB",
                           target_route=html.escape(request.url),
                           priority=2,
                           details=f"Unauthorised IP Source",
                           app_api_key=api_key,
                           user_id="None")
                raise Forbidden()
            else:
                pass


# custom rbac system
def roles_required(*required_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  # unauthorized

            current_user_role = current_user.get_role()
            data = {"role": current_user_role}
            headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
            response = requests.post(f'{BANK_API_BASE_URL}/api/get_role_permissions', json=data, verify=False,
                                     headers=headers)
            permissions_dict = response.json().get('permissions')

            # check if superadmin because instant access
            if permissions_dict['executive_permission'] == "Authorized":
                return func(*args, **kwargs)

            # if required role is ADMIN and role_permission has admin_permission
            if "MANAGER" in required_roles and permissions_dict['manager_permission'] == "Authorized":
                return func(*args, **kwargs)
            elif "IT" in required_roles and permissions_dict['IT_permission'] == "Authorized":
                return func(*args, **kwargs)
            elif "EMPLOYEE" in required_roles and permissions_dict['employee_permission'] == "Authorized":
                return func(*args, **kwargs)
            elif "USER" in required_roles and permissions_dict['user_permission'] == "Authorized":
                return func(*args, **kwargs)

            abort(403)  # Forbidden

        return wrapper

    return decorator


def permanently_delete_file_api():
    with bank_app.app_context():
        all_files = FileAPI.query.all()
        for file in all_files:
            if file.time_to_delete == None:
                pass
            elif datetime.datetime.now() > file.time_to_delete:
                db_bank.session.delete(file)
        db_bank.session.commit()
    return "Files deleted cron job"


def start_retention_period_for_files_api():
    with bank_app.app_context():
        all_files = FileAPI.query.all()
        for file in all_files:
            if file.restore_time_limit == None:
                pass
            elif file.restore_time_limit > datetime.datetime.now():
                file.set_permanently_deleted("Permanently Deleted")
                retention_period = file.bucket.lifecycle_policy.days_to_permanent_deletion
                delete_date = datetime.datetime.now() + datetime.timedelta(days=retention_period)
                file.set_time_to_delete(delete_date)
        db_bank.session.commit()
    return "Files set for permanent deletion cron job"


def rotate_keys_and_reencrypt_api(interval):
    with bank_app.app_context():
        # Get all SentinelKMS entries
        sentinel_kms_entries = SentinelKMSAPI.query.all()

        # for every key in the sentinel kms
        # i will get all files encrypted with that key
        # then i will decrypt all files with existing key
        # before reecnrypting with new key
        # then set that specific bucket key value to new key and set new date of rotation
        for sentinel_kms in sentinel_kms_entries:
            # Rotate the key every 30 days
            if datetime.datetime.now() - sentinel_kms.last_date_of_rotation > datetime.timedelta(days=interval):
                new_key = generate_fernet_key()
                encrypted_files = FileAPI.query.filter_by(bucket_id=sentinel_kms.bucket_id).all()

                for encrypted_file in encrypted_files:
                    decrypted_content = decrypt_with_key(sentinel_kms.encryption_key, encrypted_file.encrypted_content)
                    encrypted_file.encrypted_content = rotate_encrypt(new_key, decrypted_content)

                sentinel_kms.encryption_key = new_key
                sentinel_kms.last_date_of_rotation = datetime.datetime.now()

        db_bank.session.commit()


key_rotation_interval = 30


@blueprint_name.route('/')
def index():
    # need to generate the default roles that should always exist
    user_data = {"rolename": "USER",
                 'user_permission': 'Authorized',
                 'employee_permission': 'Unauthorized',
                 'IT_permission': 'Unauthorized',
                 'manager_permission': 'Unauthorized',
                 'executive_permission': 'Unauthorized', }

    employee_data = {"rolename": "EMPLOYEE",
                     'user_permission': 'Unauthorized',
                     'employee_permission': 'Authorized',
                     'IT_permission': 'Unauthorized',
                     'manager_permission': 'Unauthorized',
                     'executive_permission': 'Unauthorized', }

    IT = {"rolename": "IT",
          'user_permission': 'Unauthorized',
          'employee_permission': 'Authorized',
          'IT_permission': 'Authorized',
          'manager_permission': 'Unauthorized',
          'executive_permission': 'Unauthorized',
          }

    manager = {"rolename": "MANAGER",
               'user_permission': 'Unauthorized',
               'employee_permission': 'Authorized',
               'IT_permission': 'Authorized',
               'manager_permission': 'Authorized',
               'executive_permission': 'Unauthorized', }

    executive = {'rolename': 'EXECUTIVE',
                 'user_permission': 'Authorized',
                 'employee_permission': 'Authorized',
                 'IT_permission': 'Authorized',
                 'manager_permission': 'Authorized',
                 'executive_permission': 'Authorized', }

    headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
    response = requests.post(f'{BANK_API_BASE_URL}/api/create_role', json=IT, verify=False, headers=headers)
    response2 = requests.post(f'{BANK_API_BASE_URL}/api/create_role', json=employee_data, verify=False, headers=headers)
    response3 = requests.post(f'{BANK_API_BASE_URL}/api/create_role', json=user_data, verify=False, headers=headers)
    response4 = requests.post(f'{BANK_API_BASE_URL}/api/create_role', json=manager, verify=False, headers=headers)
    response5 = requests.post(f'{BANK_API_BASE_URL}/api/create_role', json=executive, verify=False, headers=headers)

    with bank_app.app_context():
        rotate_keys_and_reencrypt_api(key_rotation_interval)

        start_retention_period_for_files_api()
        permanently_delete_file_api()

    return render_template('index.html')





@blueprint_name.route('/login', methods=['GET', 'POST'])
@limiter.limit("100/hour", methods=["POST"])
def login():
    createloginform = CreateLoginForm(request.form)

    if current_user.is_authenticated:
        return redirect(url_for("Bank_Routes.authenticated_user", username=current_user.username))

    if request.method == "POST" and createloginform.validate_on_submit():

        if is_xss(createloginform.email.data) or is_xss(createloginform.password.data):
            add_to_log(classification="CROSS-SITE SCRIPTING",
                       target_route=html.escape(request.url),
                       priority=1,
                       details=f"Detected XSS input at login",
                       app_api_key=api_key,
                       user_id="None")

        data = {
            'email': createloginform.email.data,
            'password': createloginform.password.data,
            'rememberme': createloginform.rememberme.data
        }

        # Include the CSRF token in the headers
        # csrf_token = secrets.token_hex(16)
        #
        # # Include the API key in the headers

        data, aad = encrypt_transmission(data)


        b64_data = base64.b64encode(data).decode('utf-8')
        b64_aad = base64.b64encode(aad).decode('utf-8')

        combined_data = {"data": b64_data,
                         "aad": b64_aad}
        combined_data = json.dumps(combined_data)
        print(combined_data)

        print(session['csrf_token'])

        headers = {'X-API-Key': api_key, 'X-CSRFToken': session['csrf_token']}  # Replace 'your_api_key' with the actual API key

        # Create a custom session with the desired CSRF token

        # response = requests.post(f'{BANK_API_BASE_URL}/IAM_client_login', json=data, verify=False, headers=headers)
        response = requests.post(f'{BANK_API_BASE_URL}/IAM_client_login', json=combined_data, verify=False,
                                 headers=headers)


        print(response.text)
        if response.status_code == 200:
            user_data = response.json().get('user')
            # add the temporary creds to the usermodel
            with bank_app.app_context():
                user = UserModel.query.filter_by(id=user_data['id']).first()
                if user is None:
                    user = UserModel(id=user_data['id'], username=user_data['username'], email=user_data['email'],
                                     role_name=user_data['role'], password=user_data['password'],
                                     phone=user_data['phone'])
                    db_bank.session.add(user)
                    db_bank.session.commit()

                if user_data['enable_2fa'] == 'Not Enabled':
                    if createloginform.rememberme.data == "Enabled":
                        login_user(user, remember=True)
                    else:
                        login_user(user)
                    db_bank.session.commit()
                else:
                    return redirect(
                        url_for('Bank_Routes.confirm_2fa_login', user_id=user_data['id'],
                                email=user_data['email'],
                                rememberme=createloginform.rememberme.data))
                return redirect(url_for("Bank_Routes.authenticated_user", username=current_user.username))

        elif response.status_code == 410:
            flash("Account Locked")

        elif response.status_code == 401:
            flash("Invalid Credentials")

    # Redirect to the Bank API IAM client login page using the full URL
    # return redirect(f'{BANK_API_BASE_URL}/IAM_client_login')
    return render_template("login.html", form=createloginform, logged_in=current_user.is_authenticated)


def iam_login_2fa_email(email_to_send_to):
    email = email_to_send_to
    email_sender = 'medusapc123@gmail.com'
    email_receiver = str(email)
    app_password = "hourgtepdumwweou"

    # last for 1 minute
    otp_code = totp.now()
    body = f"""
    Your OTP is {otp_code}

        """
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em.set_content(body)

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, app_password)
            smtp.sendmail(email_sender, email_receiver, em.as_string())

        return render_template("email_success_sent.html")
    except:
        return render_template("email_failure_sent.html")


@blueprint_name.route('/confirm-login', methods=['GET', 'POST'])
def confirm_2fa_login():
    confirmloginform = Login2FAForm(request.form)
    email_received = request.args.get('email')
    rememberme = request.args.get('rememberme')
    iam_login_2fa_email(email_to_send_to=email_received)
    if request.method == "POST" and confirmloginform.validate_on_submit():
        otp_submitted = confirmloginform.OTP.data
        print(f"Current totp: {totp.now()}")
        print(f"Submitted totp: {otp_submitted}")
        with bank_app.app_context():
            if totp.verify(otp_submitted):
                userid = request.args.get('user_id')
                get_user = db_bank.session.execute(db_bank.Select(UserModel).filter_by(id=userid)).scalar_one()
                if rememberme == "Enabled":
                    login_user(get_user, remember=True)
                else:
                    login_user(get_user)
                return redirect(url_for('Bank_Routes.authenticated_user', username=get_user.get_username()))
            else:
                flash("Expired OTP token")
                return redirect(url_for('Bank_Routes.login'))

    return render_template('login_2fa_form.html', form=confirmloginform)


@blueprint_name.route('/logout')
@login_required
def logout():
    if not (
            current_user.is_authenticated):
        return redirect(url_for('Bank_Routes.index'))
    user_id = current_user.get_id()
    add_to_log(classification="JOB",
               target_route=html.escape(request.url),
               priority=0,
               details=f"User with user id of {user_id} logged out",
               app_api_key=api_key,
               user_id=user_id)
    logout_user()

    return redirect(url_for("Bank_Routes.index"))


# this route only for registering customers
@blueprint_name.route('/registerUser', methods=['GET', 'POST'])
def registerUser():
    createuserform = CreateBankUserForm(request.form)
    if request.method == "POST":
        data = {
            'email': createuserform.email.data,
            'username': createuserform.username.data,
            'password': createuserform.password.data,
            'phone': createuserform.phone.data,
            'role': "USER",
            'app_api_key': api_key
        }

        # send api request to register user
        # response = requests.post(f'{BANK_API_BASE_URL}/IAM_client_registerUser', json=data, verify=False)
        # print(response.headers)

        response = Sentinel_api.app.routes.iam_client_registerUser_SDK(data)
        print(response)
        if response != 401 and response:
            user_data = response
            with bank_app.app_context():
                user = UserModel.query.filter_by(id=user_data['id']).first()
                if user is None:
                    user = UserModel(id=user_data['id'], username=user_data['username'], email=user_data['email'],
                                     role_name=user_data['role'], password=user_data['password'],
                                     phone=user_data['phone'])  # Create User object
                    db_bank.session.add(user)
                    db_bank.session.commit()

                login_user(user)
                return redirect(url_for("Bank_Routes.authenticated_user", username=current_user.username))

    return render_template("registerUser.html", form=createuserform, logged_in=current_user.is_authenticated)


@blueprint_name.route('/admin/registerAdmin', methods=['GET', 'POST'])
def registerAdmin():
    # get all admin permission roles
    headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
    response = requests.post(f'{BANK_API_BASE_URL}/api/get_all_roles', verify=False, headers=headers)
    choices = response.json().get('choices')
    createadminform = CreateBankAdminForm(request.form)
    createadminform.role.choices = choices
    if request.method == "POST" and createadminform.validate():
        data = {
            'email': createadminform.email.data,
            'username': createadminform.username.data,
            'password': createadminform.password.data,
            'phone': createadminform.phone.data,
            'role': createadminform.role.data,
            'app_api_key': api_key
        }

        # send api request to register user
        # response = requests.post(f'{BANK_API_BASE_URL}/IAM_client_registerUser', json=data, verify=False)
        # print(response.headers)

        response = Sentinel_api.app.routes.iam_client_registerUser_SDK(data)
        if response != 401 and response:
            user_data = response
            with bank_app.app_context():
                user = UserModel.query.filter_by(id=user_data['id']).first()
                if user is None:
                    user = UserModel(id=user_data['id'], username=user_data['username'], email=user_data['email'],
                                     role_name=user_data['role'], password=user_data['password'],
                                     phone=user_data['phone'])  # Create User object
                    db_bank.session.add(user)
                    db_bank.session.commit()

                login_user(user)
                return redirect(url_for("Bank_Routes.authenticated_user", username=current_user.username))

    return render_template("registerAdmin.html", form=createadminform, logged_in=current_user.is_authenticated)


# forget password section
# i will send api request to server side first
@blueprint_name.route('/bankforgetpassword', methods=['GET', 'POST'])
def bank_forget_password():
    headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
    # forget password done server side portal
    response = requests.get(f'{BANK_API_BASE_URL}/api/IAM_forgetpassword', verify=False, headers=headers)
    if response.status_code == 200:
        return redirect(url_for("Bank_Routes.login"))
    else:
        return redirect(url_for("Bank_Routes.login"))


# test logs
def populate_five_days_logs():
    current_time = datetime.datetime.now()
    random_days = datetime.timedelta(days=random.randint(1, 5))
    for i in range(5):
        current_time = current_time + random_days

        for j in range(random.randint(10, 30)):
            # unauthorized_entry = LogsModel(
            #     log_id="LOGS_" + secrets.token_urlsafe(),
            #     user_id=current_user.get_id() if current_user.get_id() is not None else "None",
            #     classification=random.choice(["JOB", "PATH TRAVERSAL", "CROSS-SITE SCRIPTING"]),
            #     priority=random.choice([0, 1, 2, 3]),
            #     time=current_time.isoformat(),
            #     target=html.escape("http://testing"),
            #     details="TEST DATA",
            #     source_ip="113.123.1.7"
            # )
            # db.session.add(unauthorized_entry)
            # db.session.commit()
            add_to_log(
                classification=random.choice(["JOB", "PATH TRAVERSAL", "CROSS-SITE SCRIPTING"]),
                target_route=html.escape("http://testing"),
                priority=random.choice([0, 1, 2, 3]),
                details="TEST DATA",
                user_id=current_user.get_id() if current_user.get_id() is not None else "None",
                app_api_key="TESTER"
            )


# router
@blueprint_name.route("/logged_in")
@login_required
def authenticated_user():
    current_user_role = current_user.get_role()
    data = {"role": current_user_role}
    headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
    response = requests.post(f'{BANK_API_BASE_URL}/api/get_role_permissions', json=data, verify=False, headers=headers)
    permissions_dict = response.json().get('permissions')

    if permissions_dict['executive_permission'] == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Executive with user id of {current_user.get_id()} logged in",
                   app_api_key=api_key,
                   user_id=current_user.get_id())
        return redirect(url_for("Bank_Routes.get_admin_dashboard", username=flask_login.current_user.get_username(),
                                ))
    elif permissions_dict['manager_permission'] == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Manager with user id of {current_user.get_id()} logged in",
                   app_api_key=api_key,
                   user_id=current_user.get_id())
        return redirect(url_for("Bank_Routes.get_admin_dashboard", username=flask_login.current_user.get_username(),
                                ))
    elif permissions_dict['IT_permission'] == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"IT Employee with user id of {current_user.get_id()} logged in",
                   app_api_key=api_key,
                   user_id=current_user.get_id())
        return redirect(url_for("Bank_Routes.get_admin_dashboard", username=flask_login.current_user.get_username(),
                                ))
    elif permissions_dict['employee_permission'] == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Employee with user id of {current_user.get_id()} logged in",
                   app_api_key=api_key,
                   user_id=current_user.get_id())
        return redirect(url_for("Bank_Routes.get_admin_dashboard", username=flask_login.current_user.get_username(),
                                ))
    else:
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"User with user id of {current_user.get_id()} logged in",
                   app_api_key=api_key,
                   user_id=current_user.get_id())
        return redirect(url_for("Bank_Routes.get_dashboard", username=flask_login.current_user.get_username(),
                                ))


@blueprint_name.route('/populate_logs')
def populate_logs():
    populate_five_days_logs()
    return redirect(url_for('Bank_Routes.index'))


# Add your other routes and logic here
# this will be my client dashboard
# @blueprint_name.route('/client_portal/<path:username>',  methods=['GET', 'POST'])
# @login_required
# @roles_required('USER')
# def client_portal(username):
#     return f'Hello, {username}! Welcome to the Bank Portal.'

@blueprint_name.route('/client_portal/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_dashboard(username):
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"User with user id of {flask_login.current_user.get_id()} logged into dashboard",
                   app_api_key=api_key,
                   user_id=flask_login.current_user.get_id())
        return render_template("dashboard_user.html", username=username)
    else:
        return redirect(url_for('Bank_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))


# page to edit customer details
@blueprint_name.route('/client_portal/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def userProfile(username):
    updateuserform = UpdateBankUserForm(request.form)
    # if im updating
    if request.method == "POST" and updateuserform.validate():
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data
        old_password = updateuserform.old_password.data.encode("utf-8")
        enable_2fa = updateuserform.enable_2fa.data
        if bcrypt.checkpw(old_password, flask_login.current_user.get_password().encode()):
            new_password = updateuserform.password.data
            new_password = new_password.encode('utf-8')
            mySalt = bcrypt.gensalt()
            pwd_hash = bcrypt.hashpw(new_password, mySalt)
            pwd_hash = pwd_hash.decode('utf-8')
            data = {
                "target_email": flask_login.current_user.email,
                "email": new_email,
                "username": new_username,
                "phone": new_phone,
                "password": pwd_hash,
                "enable_2fa": enable_2fa}

            # with app.app_context():
            #  current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
            with bank_app.app_context():
                current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
                current_user_to_update.username = new_username
                current_user_to_update.email = new_email
                current_user_to_update.password = pwd_hash
                db_bank.session.commit()

            headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
            response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_update_user', verify=False,
                                     headers=headers, json=data)
            # print(current_user_to_update[0])

            # Reattach the object to the session
            with bank_app.app_context():
                current_user_to_update = db_bank.session.merge(current_user_to_update)
                login_user(current_user_to_update, remember=True)
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"User with user id of {current_user_to_update.get_id()} updated profile",
                       app_api_key=api_key,
                       user_id=current_user_to_update.get_id())
            return redirect(url_for('Bank_Routes.get_dashboard', username=current_user_to_update.get_username(),
                                    logged_in=flask_login.current_user.is_authenticated,
                                    ))
        else:
            return redirect(url_for('Bank_Routes.userProfile', username=flask_login.current_user.get_username(),
                                    ))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            with bank_app.app_context():
                current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.email).first()
            # retrieve user via email
            data = {"email": current_user_to_update.get_email()}
            headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
            response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_retrieve_user', verify=False,
                                     headers=headers, json=data)
            user_data = response.json().get('user')
            updateuserform.username.data = user_data['username']
            updateuserform.email.data = user_data['email']
            updateuserform.phone.data = user_data['phone']
            updateuserform.enable_2fa.data = user_data['enable_2fa']

            return render_template("dashboard_user_profile.html", username=username,
                                   form=updateuserform)

        else:
            return redirect(url_for('Bank_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                    ))


@blueprint_name.route('/client_portal/dashboard/<path:username>/history', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_history_dashboard(username):
    if username == flask_login.current_user.get_username():
        current_user = username
        fileform = VerifyFileForm(request.form)
        with bank_app.app_context():
            current_user_account_id = flask_login.current_user.account.account_id
            transaction_model = TransactionModel.query.filter(
                (TransactionModel.src_account_id == current_user_account_id) |
                (TransactionModel.dst_account_id == current_user_account_id)
            ).all()

            verify_blockchain()

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"User with user id of {flask_login.current_user.get_id()} accessed history dashboard.",
                   app_api_key=api_key,
                   user_id=flask_login.current_user.get_id())

        return render_template("dashboard_user_history.html", username=username, transaction_model=transaction_model,
                               fileform=fileform)
    else:
        return redirect(url_for('Bank_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))


def _build_itemized_description_table(transaction_model):
    table_1 = Table(number_of_rows=len(transaction_model) + 1, number_of_columns=5)
    for h in ["Date", "From", "To", "Amount", "Type"]:
        table_1.add(
            TableCell(
                Paragraph(h, font_color=X11Color("White")),
                background_color=HexColor("7986cb")
            )
        )

    odd_color = HexColor("BBBBBB")
    even_color = HexColor("FFFFFF")

    for transaction in transaction_model:
        c = even_color if transaction_model.index(transaction) % 2 == 0 else odd_color
        table_1.add(TableCell(Paragraph(str(transaction.get_time())), background_color=c))
        table_1.add(TableCell(Paragraph(transaction.src_username), background_color=c))
        table_1.add(TableCell(Paragraph(transaction.dst_username), background_color=c))
        table_1.add(TableCell(Paragraph(str(transaction.transaction_amount)), background_color=c))
        table_1.add(TableCell(Paragraph(transaction.transaction_type), background_color=c))

    table_1.set_padding_on_all_cells(Decimal(2), Decimal(2), Decimal(2), Decimal(2))
    table_1.no_borders()

    print("Itemized Table Success")
    return table_1


# Invoice Information table
def _build_invoice_information():
    table_1 = Table(number_of_rows=5, number_of_columns=3)
    random_serial_num = random.randint(1000000000, 9999999999)
    table_1.add(Paragraph("S/N: STATEMENT-" + str(random_serial_num)))
    table_1.add(Paragraph(""))
    table_1.add(
        Paragraph("Consolidated Statement", font="Helvetica-Bold", horizontal_alignment=Alignment.RIGHT))

    table_1.add(Paragraph("Tom Tan"))
    table_1.add(Paragraph(""))
    table_1.add(Paragraph(""))

    table_1.add(Paragraph(""))
    table_1.add(Paragraph(""))
    table_1.add(Paragraph(""))

    now = datetime.datetime.now().date()
    account_sum_string = "Account Summary as of " + str(now)

    # Create a TableCell and add the Paragraph to it
    cell = TableCell(
        Paragraph(account_sum_string, font="Helvetica-Bold", font_size=Decimal(20)),
        column_span=2  # Set column_span to 2 to make the cell span across 2 columns
    )

    table_1.add(cell)
    table_1.add(Paragraph(""))

    table_1.add(Paragraph("Deposits", font="Helvetica-Bold", font_size=Decimal(15),
                          background_color=HexColor("#808080"),
                          font_color=X11Color("White")
                          ))
    table_1.add(Paragraph(""))
    table_1.add(Paragraph(""))

    table_1.set_padding_on_all_cells(Decimal(2), Decimal(2), Decimal(2), Decimal(2), )
    table_1.no_borders()
    return table_1


@blueprint_name.route('/client_portal/dashboard/<path:username>/history/download_statement', methods=['POST'])
@login_required
@roles_required('USER')
def download_bank_statement(username):
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            # Create invoice
            buffer = BytesIO()
            pdf = Document()

            # add page
            page = Page()
            pdf.add_page(page)

            page_layout = SingleColumnLayout(page)
            page_layout.vertical_margin = page.get_page_info().get_height() * Decimal(0.02)

            # Add image to the top right corner
            image_width = Decimal(120)
            image_height = Decimal(80)

            image = Image(
                "https://static.vecteezy.com/system/resources/previews/007/741/295/original/medusa-logo-natural-beautiful-woman-s-face-snakes-line-art-logo-for-beauty-salon-free-vector.jpg",
                width=image_width,
                height=image_height,
                horizontal_alignment=Alignment.RIGHT
            )
            page_layout.add(image)

            page_layout.add(_build_invoice_information())

            # Invoice Information table
            # page_layout.add(_build_invoice_information())

            # add empty paragraph for spacing
            page_layout.add(Paragraph(""))

            with bank_app.app_context():
                current_user_account_id = flask_login.current_user.account.account_id
                transaction_info = TransactionModel.query.filter(
                    (TransactionModel.src_account_id == current_user_account_id) |
                    (TransactionModel.dst_account_id == current_user_account_id)
                ).all()

            page_layout.add(_build_itemized_description_table(transaction_info))

            # add outline
            pdf.add_outline("statement", 0, DestinationType.FIT, page_nr=0)
            # Return the PDF as a response
            # store the PDF
            with open("output.pdf", "wb") as pdf_file_handle:
                PDF.dumps(pdf_file_handle, pdf)

            # run the verifier
            elliptic_keys = generate_elliptic_keys()

            # add metadata to pdf
            with open("output.pdf", 'rb') as input_file:
                reader = PdfReader(input_file)
                writer = PdfWriter()
                # Add all pages to the writer
                for page in reader.pages:
                    writer.add_page(page)

                writer.add_metadata(
                    {
                        "/Key": elliptic_keys["serialised_public_key"],
                        "/Producer": "Global Elite Bank",
                    }
                )

                with open("secure-output.pdf", "wb") as f:
                    writer.write(f)

            # get hash of pdf
            hash_to_sign = get_hash_of_pdf("secure-output.pdf")
            generate_verifier(hash_to_sign, elliptic_keys["private_key"])

            with open("secure-output.pdf", 'rb') as pdf_file:
                buffer.write(pdf_file.read())
            buffer.seek(0)
            download_name = str(datetime.datetime.now().date()) + "-statement.pdf"

            return send_file(buffer, as_attachment=True, download_name=download_name,
                             mimetype='application/pdf')

    else:
        return redirect(url_for('Bank_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))


# document verifier
@blueprint_name.route('/client_portal/dashboard/<path:username>/history/verify_statement', methods=['POST'])
@login_required
@roles_required('USER')
def verify_bank_statement(username):
    # get metadata of file
    fileform = VerifyFileForm(request.form)
    if request.method == "POST":
        try:
            file = request.files['file']
            filename = secure_filename(file.filename)
            current_directory = os.getcwd()  # Get the current directory
            file_path = os.path.join(current_directory, filename)  # Define the path to save the file
            file.save(file_path)

            with open(file_path, "rb") as input_file:
                reader = PdfReader(input_file)
                meta = reader.metadata
                metadata_key = meta['/Key']
                print(metadata_key)

            hash_to_verify = get_hash_of_pdf(file_path)
            print(hash_to_verify)

            if elliptic_verify(hash_to_verify, metadata_key):
                flash('Verified', 'success')
            else:
                flash('Not Verified', 'error')

            os.remove(file_path)
            return redirect(
                url_for('Bank_Routes.get_history_dashboard', username=flask_login.current_user.get_username(),
                        ))

        except Exception as e:
            flash('Not Verified', 'error')
            return redirect(
                url_for('Bank_Routes.get_history_dashboard', username=flask_login.current_user.get_username(),
                        ))


# blockchain ganache use lethal-income
# try to implement blockchain verification
from web3 import Web3
from Bank_app.app.blockchain_address import *

# Contract address and ABI (obtained from deployment)
contract_address = contractAddress  # Replace with your deployed contract address
contract_abi = [
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "logHash",
                "type": "string"
            }
        ],
        "name": "LogHashStored",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": False,
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "srcAccountId",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "srcUsername",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "dstAccountId",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "dstUsername",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "uint256",
                "name": "time",
                "type": "uint256"
            },
            {
                "indexed": False,
                "internalType": "uint256",
                "name": "transactionAmount",
                "type": "uint256"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "transactionType",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "combinedHash",
                "type": "string"
            }
        ],
        "name": "LogTransactionStored",
        "type": "event"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "name": "logHashes",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "name": "transactions",
        "outputs": [
            {
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "srcAccountId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "srcUsername",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "dstAccountId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "dstUsername",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "time",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "transactionAmount",
                "type": "uint256"
            },
            {
                "internalType": "string",
                "name": "transactionType",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "combinedHash",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "srcAccountId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "srcUsername",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "dstAccountId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "dstUsername",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "time",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "transactionAmount",
                "type": "uint256"
            },
            {
                "internalType": "string",
                "name": "transactionType",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "combinedHash",
                "type": "string"
            }
        ],
        "name": "storeTransaction",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "logHash",
                "type": "string"
            }
        ],
        "name": "storeHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            }
        ],
        "name": "getHash",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "transactionId",
                "type": "string"
            }
        ],
        "name": "getTransactionDetails",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            },
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

account_address = accountAddress
private_key = privateKey

# Initialize web3 provider
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))

# w3 = Web3(Web3.HTTPProvider('https://responsive-smart-bush.ethereum-sepolia.quiknode.pro/3b02a33a557a0ebd549b293f39a7fd22cb4e0288/'))
# w3 = Web3(Web3.HTTPProvider('https://eth-sepolia.g.alchemy.com/v2/6ZCVOLqzi8tPWpC_OovZJEoZBW6bMs92'))

# Get contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)


def calculate_hash(transact_id, src_account_id, dst_account_id, time, transaction_amount, transaction_type,
                   src_username, dst_username):
    # Hash the concatenated transaction details
    data_to_hash = f"{transact_id}{src_account_id}{dst_account_id}{time}{float(transaction_amount)}{transaction_type}{src_username}{dst_username}"
    # print(f"Data to hash: {data_to_hash}")
    return hashlib.sha256(data_to_hash.encode()).hexdigest()


def add_transaction_helper(src_account_id, dst_account_id, time, transaction_amount, transaction_type, src_username,
                           dst_username):
    transact_id = "TRANSACT" + str(uuid.uuid4())
    src_account_id = src_account_id
    dst_account_id = dst_account_id
    time = time
    transaction_amount = transaction_amount
    transaction_type = transaction_type
    src_username = src_username
    dst_username = dst_username

    with bank_app.app_context():
        new_transaction = TransactionModel(transact_id=transact_id,
                                           src_account_id=src_account_id,
                                           dst_account_id=dst_account_id,
                                           time=time,
                                           transaction_amount=transaction_amount,
                                           transaction_type=transaction_type,
                                           src_username=src_username,
                                           dst_username=dst_username)
        db_bank.session.add(new_transaction)
        db_bank.session.commit()

        # Calculate the hash of the transaction data
        calculated_hash = calculate_hash(transact_id, src_account_id, dst_account_id, int(time.timestamp()),
                                         transaction_amount,
                                         transaction_type, src_username, dst_username)

        print(f"Calculated_hash:{calculated_hash}")
        print(time)
        print(time.timestamp())

        new_transaction.set_combined_hash(calculated_hash)
        db_bank.session.commit()



        # tx_hash = contract.functions.storeTransaction(
        #     transact_id, src_account_id, src_username, dst_account_id, dst_username, int(time.timestamp()),
        #     transaction_amount, transaction_type, calculated_hash
        # ).transact({'from': account_address})

        # Sign the transaction locally
        transaction = contract.functions.storeTransaction(
            transact_id, src_account_id, src_username, dst_account_id, dst_username, int(time.timestamp()),
            transaction_amount, transaction_type, calculated_hash
        )

        # Get the nonce
        nonce = w3.eth.get_transaction_count(account_address)

        # estimate gas
        estimated_gas = transaction.estimate_gas()
        print("Estimate gas")
        print(estimated_gas)


        # Build the transaction
        transaction_dict = transaction.build_transaction({
            'gas': estimated_gas + 10000,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
        })

        # Sign the transaction
        signed_transaction = w3.eth.account.sign_transaction(transaction_dict, private_key)

        # Send the signed transaction
        raw_transaction = signed_transaction.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw_transaction)



        # Get transaction receipt
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print("Transaction receipt mined:")
        pprint.pprint(dict(tx_receipt))

        ethereum_hash = tx_receipt.transactionHash

        new_transaction.set_ethereum_hash(ethereum_hash)

        db_bank.session.commit()


def verify_blockchain():
    with bank_app.app_context():
        transactions = TransactionModel.query.all()

        for transaction in transactions:
            tx_hash_from_db = transaction.get_ethereum_hash()
            calculated_hash_from_db = transaction.get_combined_hash()

            tx_hash_from_db = bytes.fromhex(tx_hash_from_db[2:]).hex()

            try:
                # Get transaction receipt from Ganache based on transaction ID or any other identifier you use
                tx_receipt = w3.eth.get_transaction_receipt(tx_hash_from_db)
                tx_hash_from_blockchain = tx_receipt.transactionHash if tx_receipt else None
                print(f"Expected: {tx_receipt.transactionHash.hex()}")
                print(f"Got: {'0x' + tx_hash_from_db}")

                if '0x' + tx_hash_from_db == tx_receipt.transactionHash.hex():
                    print(f"Transaction {transaction.transaction_id}: Hashes match")
                else:
                    print(f"Transaction {transaction.transaction_id}: Hashes do not match")

                # now i need to compare the combined data
                # i store the combinedData as a field in my smart contract so i retrieve it and compare with my postgres data
                # Recalculate the hash based on the stored details
                recalculated_hash = calculate_hash(transaction.transaction_id, transaction.src_account_id,
                                                   transaction.dst_account_id, int(transaction.time.timestamp()),
                                                   transaction.transaction_amount, transaction.transaction_type,
                                                   transaction.src_username, transaction.dst_username)
                # expected_hash = transaction.get_combined_hash()
                # print(expected_hash)
                print(recalculated_hash)
                transaction_details = contract.functions.getTransactionDetails(str(transaction.transaction_id)).call()
                src_account_id, src_username, dst_account_id, dst_username, time, transaction_amount, transaction_type, combined_hash = transaction_details
                print("Hash:" + combined_hash)

                try:

                    if recalculated_hash != combined_hash:
                        print("No data match")
                        # fix the data
                        transaction.src_account_id = src_account_id
                        transaction.dst_account_id = dst_account_id,
                        transaction.src_username = src_username
                        transaction.dst_username = dst_username
                        transaction.transaction_amount = transaction_amount
                        transaction.transaction_type = transaction_type
                        transaction.combined_hash = combined_hash

                        db_bank.session.commit()

                    else:
                        print("Data match")
                        print(time)
                        print(datetime.datetime.utcfromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S.%f'))
                except Exception as e:
                    print(f"Error retrieving combined data: {e}")
            except:
                pass


def transfer_money(src_username, dst_username, amount):
    # deduct from src first
    with bank_app.app_context():
        src_user = UserModel.query.filter_by(username=src_username).first()
        dst_user = UserModel.query.filter_by(username=dst_username).first()
        src_account = AccountModel.query.filter_by(user_id=src_user.get_id()).first()
        dst_account = AccountModel.query.filter_by(user_id=dst_user.get_id()).first()
        if src_account.get_balance() >= amount and src_account is not None and dst_account is not None:
            new_balance = src_account.get_balance() - amount
            src_account.set_balance(new_balance)

            new_balance_dst = dst_account.get_balance() + amount
            dst_account.set_balance(new_balance_dst)

            add_transaction_helper(src_account_id=src_account.get_id(),
                                   dst_account_id=dst_account.get_id(),
                                   time=datetime.datetime.now(),
                                   transaction_amount=amount,
                                   transaction_type="TRANSFER",
                                   src_username=src_user.get_username(),
                                   dst_username=dst_user.get_username())

            db_bank.session.commit()

            return "Success"

        else:
            return "Insufficient funds"


def withdraw_money(src_username, amount):
    # deduct from src first
    with bank_app.app_context():
        src_user = UserModel.query.filter_by(username=src_username).first()
        src_account = AccountModel.query.filter_by(user_id=src_user.get_id()).first()
        if src_account.get_balance() >= amount and src_account is not None:
            new_balance = src_account.get_balance() - amount
            src_account.set_balance(new_balance)

            # new_transaction = TransactionModel(src_account_id=src_account.get_id(),
            #                                    dst_account_id=src_account.get_id(),
            #                                    time=datetime.datetime.now(),
            #                                    transaction_amount=amount,
            #                                    transaction_type='WITHDRAW',
            #                                    src_username=src_user.get_username(),
            #                                    dst_username=src_user.get_username()
            #                                    )
            # db_bank.session.add(new_transaction)
            # db_bank.session.commit()
            add_transaction_helper(src_account_id=src_account.get_id(),
                                   dst_account_id=src_account.get_id(),
                                   time=datetime.datetime.now(),
                                   transaction_amount=amount,
                                   transaction_type='WITHDRAW',
                                   src_username=src_user.get_username(),
                                   dst_username=src_user.get_username())

            db_bank.session.commit()
            return "Success"
        else:
            return "Insufficient funds"


def deposit_money(src_username, amount):
    with bank_app.app_context():
        src_user = UserModel.query.filter_by(username=src_username).first()
        src_account = AccountModel.query.filter_by(user_id=src_user.get_id()).first()
        if src_account is not None:
            new_balance = src_account.get_balance() + amount
            src_account.set_balance(new_balance)

            add_transaction_helper(src_account_id=src_account.get_id(),
                                   dst_account_id=src_account.get_id(),
                                   time=datetime.datetime.now(),
                                   transaction_amount=amount,
                                   transaction_type='DEPOSIT',
                                   src_username=src_user.get_username(),
                                   dst_username=src_user.get_username())

            db_bank.session.commit()

            return "Success"
        else:
            return "Invalid user"


@blueprint_name.route('/client_portal/dashboard/<path:username>/transfer', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_transfer_dashboard(username):
    transferform = transfer_form(request.form)
    if request.method == "POST" and transferform.validate():
        transfer_money(src_username=flask_login.current_user.get_username(),
                       dst_username=transferform.dst_account.data,
                       amount=transferform.amount.data)
        return redirect(url_for('Bank_Routes.get_transfer_dashboard', username=flask_login.current_user.get_username(),
                                ))
    else:
        with bank_app.app_context():
            balance = AccountModel.query.filter_by(user_id=flask_login.current_user.get_id()).first().get_balance()
        return render_template("dashboard_user_transfer.html", username=username,
                               form=transferform, balance=balance)


@blueprint_name.route('/client_portal/dashboard/<path:username>/DepositWithdraw', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_depositWithdraw_dashboard(username):
    form = deposit_withdraw_form(request.form)
    if request.method == "POST" and form.validate():
        if form.option.data == "DEPOSIT":
            deposit_money(src_username=username, amount=form.amount.data)
        else:
            withdraw_money(src_username=username, amount=form.amount.data)

        return redirect(
            url_for('Bank_Routes.get_depositWithdraw_dashboard', username=flask_login.current_user.get_username(),
                    ))

    else:
        with bank_app.app_context():
            balance = AccountModel.query.filter_by(user_id=flask_login.current_user.get_id()).first().get_balance()
        return render_template("dashboard_user_depositWithdraw.html", username=username,
                               form=form, balance=balance)


# need to do for admin side includes superadmin and employee

@blueprint_name.route('/admin_portal/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def admin_portal(username):
    return f'Hello, {username}! Welcome to the Employee Bank Portal.'


@blueprint_name.route('/deleteUser', methods=['GET', 'POST'])
@login_required
def deleteUser():
    with bank_app.app_context():
        current_user_to_delete = UserModel.query.filter_by(email=current_user.get_email()).first()

        current_account_to_delete = AccountModel.query.filter_by(user_id=current_user.get_id()).first()

        # need to make api call to delete user in iam
        data = {"user": current_user_to_delete.get_id()}
        headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
        response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_delete_user', verify=False,
                                 headers=headers, json=data)

        try:
            # delete account first
            if current_user_to_delete.get_role() == "USER":
                db_bank.session.delete(current_account_to_delete)

            # then logout user
            logout_user()

            # then delete
            db_bank.session.delete(UserModel.query.filter_by(id=current_user_to_delete.get_id()).first())

            # db.session.delete(current_user_to_delete)
            db_bank.session.commit()
        except IntegrityError as e:
            db_bank.session.rollback()
            print(f"IntegrityError: {str(e)}")

    # app.logger.info("User deleted")
    return redirect(url_for("Bank_Routes.index"))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def userProfile_admin(username):
    updateuserform = UpdateBankUserForm(request.form)
    # if im updating
    if request.method == "POST" and updateuserform.validate():
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data
        old_password = updateuserform.old_password.data.encode("utf-8")
        enable_2fa = updateuserform.enable_2fa.data
        if bcrypt.checkpw(old_password, flask_login.current_user.get_password().encode()):
            new_password = updateuserform.password.data
            new_password = new_password.encode('utf-8')
            mySalt = bcrypt.gensalt()
            pwd_hash = bcrypt.hashpw(new_password, mySalt)
            pwd_hash = pwd_hash.decode('utf-8')
            data = {
                "target_email": flask_login.current_user.email,
                "email": new_email,
                "username": new_username,
                "phone": new_phone,
                "password": pwd_hash,
                "enable_2fa": enable_2fa}

            # with app.app_context():
            #  current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
            with bank_app.app_context():
                current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
                current_user_to_update.username = new_username
                current_user_to_update.email = new_email
                current_user_to_update.password = pwd_hash
                db_bank.session.commit()

            headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
            response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_update_user', verify=False,
                                     headers=headers, json=data)
            # print(current_user_to_update[0])

            # Reattach the object to the session
            with bank_app.app_context():
                current_user_to_update = db_bank.session.merge(current_user_to_update)
                login_user(current_user_to_update, remember=True)
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"User with user id of {current_user_to_update.get_id()} updated profile",
                       app_api_key=api_key,
                       user_id=current_user_to_update.get_id())
            return redirect(url_for('Bank_Routes.get_admin_dashboard', username=current_user_to_update.get_username(),
                                    logged_in=flask_login.current_user.is_authenticated,
                                    ))
        else:
            return redirect(url_for('Bank_Routes.userProfile_admin', username=flask_login.current_user.get_username(),
                                    ))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            with bank_app.app_context():
                current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.email).first()
            # retrieve user via email
            data = {"email": current_user_to_update.get_email()}
            headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
            response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_retrieve_user', verify=False,
                                     headers=headers, json=data)
            user_data = response.json().get('user')
            updateuserform.username.data = user_data['username']
            updateuserform.email.data = user_data['email']
            updateuserform.phone.data = user_data['phone']
            updateuserform.enable_2fa.data = user_data['enable_2fa']

            return render_template("dashboard_admin_user_profile.html", username=username,
                                   form=updateuserform)

        else:
            return redirect(url_for('Bank_Routes.get_admin_dashboard', username=flask_login.current_user.get_username(),
                                    ))


@blueprint_name.route('/admin_portal/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_admin_dashboard(username):
    if username == flask_login.current_user.get_username():
        current_user = username

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Employee with user id of {flask_login.current_user.get_id()} logged into dashboard",
                   app_api_key=api_key,
                   user_id=flask_login.current_user.get_id())
        return render_template("dashboard_admin.html", username=username)
    else:
        return redirect(url_for('Bank_Routes.get_admin_dashboard', username=flask_login.current_user.get_username(),
                                ))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/all_transactions', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_admin_transaction_dashboard(username):
    if username == flask_login.current_user.get_username():
        current_user = username

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Employee with user id of {flask_login.current_user.get_id()} logged into transaction dashboard",
                   app_api_key=api_key,
                   user_id=flask_login.current_user.get_id())

        with bank_app.app_context():
            transaction_model = TransactionModel.query.all()
        return render_template("dashboard_admin_history.html", username=username, transaction_model=transaction_model)
    else:
        return redirect(url_for('Bank_Routes.get_admin_dashboard', username=flask_login.current_user.get_username(),
                                ))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/all_users', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_admin_user_dashboard(username):
    current_user = username
    # if not(flask_login.current_user.get_role() == "ADMIN"):
    #     return redirect(url_for('index'))
    # create a form to update the user using a modal
    updateuserform = UpdateBankExecForm(request.form)

    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)

        # headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
        # response = requests.get(f'{BANK_API_BASE_URL}/api/get_role_permissions', verify=False,
        #                          headers=headers)

        # get all customers for employees
        with bank_app.app_context():

            all_customers = UserModel.query.filter(UserModel.role_name == "USER").all()

            # get all employees for IT and managers
            all_employees = UserModel.query.filter(UserModel.role_name == "EMPLOYEE").all()

            # get all employees, IT and manager for exec
            all_managers = UserModel.query.filter(UserModel.role_name == "MANAGER").all()

            all_IT = UserModel.query.filter(UserModel.role_name == "IT").all()

            all_exec = UserModel.query.filter(UserModel.role_name == "EXECUTIVE").all()

            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"Bank Employee with user id of {flask_login.current_user.get_id()} accessed user management interface.",
                       app_api_key=api_key,
                       user_id=flask_login.current_user.get_id())
            return render_template("dashboard_admin_usermanage.html", username=username,
                                   usermodel=all_customers, employeemodel=all_employees, managersmodel=all_managers,
                                   ITmodel=all_IT, execmodel=all_exec, updateform=updateuserform)
    else:
        return redirect(url_for('Bank_Routes.authenticated_user'))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/all_users/update', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def update_user_admin(username):
    target_email = request.args.get('email')
    updateuserform = UpdateBankExecForm(request.form)
    if request.method == "POST":
        target_email = request.args.get('email')
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data

        new_password = updateuserform.password.data
        new_password = new_password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')
        data = {
            "target_email": flask_login.current_user.email,
            "email": new_email,
            "username": new_username,
            "phone": new_phone,
            "password": pwd_hash,
        }

        # with app.app_context():
        #  current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
        with bank_app.app_context():
            current_user_to_update = UserModel.query.filter_by(email=target_email).first()
            current_user_to_update.username = new_username
            current_user_to_update.email = new_email
            current_user_to_update.password = pwd_hash
            current_user_to_update.phone = new_phone
            db_bank.session.commit()

        headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
        response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_update_user_by_admin', verify=False,
                                 headers=headers, json=data)

        return redirect(
            url_for("Bank_Routes.get_admin_user_dashboard", username=flask_login.current_user.get_username()))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/all_users/delete', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def delete_user_admin(username):
    if request.method == "POST":
        target_email = request.args.get('email')
        with bank_app.app_context():
            current_user_to_delete = UserModel.query.filter_by(email=target_email).first()

            current_account_to_delete = AccountModel.query.filter_by(user_id=current_user_to_delete.get_id()).first()

            # need to make api call to delete user in iam
            data = {"user": current_user_to_delete.get_id()}
            headers = {'X-API-Key': api_key}  # Replace 'your_api_key' with the actual API key
            response = requests.post(f'{BANK_API_BASE_URL}/api/IAM_client_delete_user', verify=False,
                                     headers=headers, json=data)

            try:
                # delete account first
                if current_user_to_delete.get_role() == "USER":
                    db_bank.session.delete(current_account_to_delete)

                # then delete
                db_bank.session.delete(UserModel.query.filter_by(id=current_user_to_delete.get_id()).first())

                # db.session.delete(current_user_to_delete)
                db_bank.session.commit()
            except IntegrityError as e:
                print(e)
                db_bank.session.rollback()
                print(f"IntegrityError: {str(e)}")

        # app.logger.info("User deleted")
        return redirect(url_for("Bank_Routes.get_admin_user_dashboard", username=current_user.get_username()))


# to edit the roles, login to the account for sentinel that has the same api key as this flask app

# transaction dashboard
@blueprint_name.route('/admin_portal/dashboard/<path:username>/finance', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_admin_finance_dashboard(username):
    if username == flask_login.current_user.get_username():
        current_user = username

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} accessed finance dashboard.",
                   app_api_key=api_key,
                   user_id=flask_login.current_user.get_id())

        return render_template("dashboard_admin_finance.html", username=username)
    else:
        return redirect(url_for('Bank_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/buckets', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_available_buckets(username):
    if username == flask_login.current_user.get_username():
        with bank_app.app_context():
            # if request.method == "POST":
            #         with app.app_context():
            #             bucket_id = request.args.get('bucket_id')

            # get all the buckets by user and privilege
            # buckets = BucketAPI.query.all()

            # owned_buckets = []
            # for buc in buckets:
            #     owned_buckets.append(buc.id)
            names_to_match = get_bucket_privilege(flask_login.current_user.get_role())
            conditions = or_(BucketAPI.name == name for name in names_to_match)

            buckets = BucketAPI.query.filter(conditions).all()

            # this page will show in a table what buckets the user created in a table
            # there will be links like the blog table, to update and delete buckets
            # when you click on view bucket, it should show a list of files that is in the bucket and a bucket cannot be deleted
            # until bucket is empty
            return render_template("dashboard_admin_buckets.html", username=flask_login.current_user.get_username(),
                                   bucketmodel=buckets,
                                   )


def get_bucket_privilege(role_name):
    with bank_app.app_context():
        if role_name == "EXECUTIVE":
            return ["Public", "Internal", "Confidential", "Restricted"]
        elif role_name == "MANAGER" or role_name == "IT":
            return ["Public", "Internal", "Confidential"]
        elif role_name == "EMPLOYEE":
            return ["Public", "Internal"]
        else:
            return ["Public"]


# get files from available buckets
@blueprint_name.route('/admin_portal/dashboard/<path:username>/files', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_admin_files_by_user(username):
    with bank_app.app_context():
        uploadform = UploadFileFormAPI(request.form)

        if username == flask_login.current_user.get_username():

            # get all the buckets by user
            # Construct an OR condition to match any of the names in the list
            names_to_match = get_bucket_privilege(flask_login.current_user.get_role())
            conditions = or_(BucketAPI.name == name for name in names_to_match)

            buckets = BucketAPI.query.filter(conditions).all()

            bucket_id_available = []
            for bucket in buckets:
                bucket_id_available.append(bucket.id)

            bucket_retrieval_condition = or_(FileAPI.bucket_id == name for name in bucket_id_available)

            files = FileAPI.query.filter(bucket_retrieval_condition).all()

            # get shared files
            # i need to get the shared buckets (those not owned by me only)
            # get all the buckets by user

            # only show files where restore time limit is None or not expired means still can backup

            # this page will show in a table what buckets the user created in a table
            # there will be links like the blog table, to update and delete buckets
            # when you click on view bucket, it should show a list of files that is in the bucket and a bucket cannot be deleted
            # until bucket is empty
            return render_template("dashboard_admin_files.html", username=flask_login.current_user.get_username(),
                                   filemodel=files,
                                   uploadform=uploadform)

        else:
            return redirect(url_for('Bank_Routes.authenticated_user'))


def createBucket(name):
    with bank_app.app_context():
        if BucketAPI.query.filter_by(name=name).first() is None:
            new_lifecycle_policy = LifecyclePolicyAPI(
                days_to_archive=90,
                days_to_permanent_deletion=180,
            )

            db_bank.session.add(new_lifecycle_policy)
            db_bank.session.commit()

            # lifecycle policy attached to bucket
            new_bucket = BucketAPI(name=name,
                                   lifecycle_policy_id=new_lifecycle_policy.id,
                                   )

            db_bank.session.add(new_bucket)
            db_bank.session.commit()

            # need to create the kms key associated with the bucket
            new_key = SentinelKMSAPI(key=generate_fernet_key(),
                                     bucket_id=new_bucket.id)

            db_bank.session.add(new_key)
            db_bank.session.commit()
            new_bucket.set_sentinel_kms_id(new_key.id)

            db_bank.session.commit()


@blueprint_name.route('/demo/create_bucket', methods=['GET'])
def createbucket():
    for i in ["Public", "Internal", "Confidential", "Restricted"]:
        createBucket(i)
    return redirect(url_for("Bank_Routes.index"))

from Sentinel_api.SentinelSuite.secure_storage_center import cloudmersivescan_api

@blueprint_name.route('/admin_portal/dashboard/<path:username>/files/upload', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def upload_file_to_scc(username):
    uploaded_file = request.files['file']
    file_details = UploadFileFormAPI(request.form)
    tags_selected = file_details.existing_tags.data
    # print(tags_selected)

    if "Sensitive" in tags_selected:
        bucket_name = "Restricted"
    elif "Report" in tags_selected or "Finance" in tags_selected:
        bucket_name = "Confidential"
    elif "Internal" in tags_selected:
        bucket_name = "Internal"
    elif "Announcements" in tags_selected or "Events" in tags_selected or "General" in tags_selected:
        bucket_name = "Public"
    else:
        bucket_name = "Internal"

    with bank_app.app_context():
        target_bucket = BucketAPI.query.filter_by(name=bucket_name).first()
        target_bucket_key = target_bucket.sentinel_kms.get_key()
        if uploaded_file and username == flask_login.current_user.get_username():
            data = cloudmersivescan_api(uploaded_file.stream, uploaded_file.filename)
            # retrieve key from associated bucket
            encrypted_content = encrypt_with_key(key=target_bucket_key, data=data)
            new_file = FileAPI(
                id="FILEAPI" + str(uuid.uuid4()),
                name=uploaded_file.filename,
                encrypted_content=encrypted_content,
                bucket_id=target_bucket.id,
                user_id=flask_login.current_user.get_id())
            db_bank.session.add(new_file)
            db_bank.session.commit()
            return redirect(
                url_for('Bank_Routes.get_admin_files_by_user', username=flask_login.current_user.get_username()))
        else:
            return redirect(url_for('Bank_Routes.authenticated_user'))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/files/deleteFile', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def delete_file_to_scc_temporarily(username):
    if username == flask_login.current_user.get_username():
        with bank_app.app_context():
            # check if bucket is empty
            file_id = request.args.get('file_id')
            # retrieve the file to temp delete
            target_file = FileAPI.query.get(file_id)
            # now change the file marker for temp_delete to Deleted
            target_file.set_temp_deleted("Deleted")

            # then set time for permanent deletion
            scheduled_time = datetime.datetime.now() + datetime.timedelta(
                days=target_file.bucket.lifecycle_policy.days_to_archive)
            target_file.set_restore_time_limit(scheduled_time)

            db_bank.session.commit()
        return redirect(
            url_for('Bank_Routes.get_admin_files_by_user', username=flask_login.current_user.get_username()))
    else:
        return redirect(url_for('Bank_Routes.authenticated_user'))


@blueprint_name.route('/admin_portal/dashboard/<path:username>/files/downloadFile', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def downloadFile(username):
    if username == flask_login.current_user.get_username():
        with bank_app.app_context():
            # check if bucket is empty
            file_id = request.args.get('file_id')
            file_to_download = FileAPI.query.get(file_id)
            target_bucket_key = file_to_download.bucket.sentinel_kms.encryption_key
            decrypted_content = decrypt_with_key(target_bucket_key, file_to_download.encrypted_content)
            temp_file_path = f'temp_{file_to_download.id}_{file_to_download.name}'  # Unique file name
            # with open(temp_file_path, 'wb') as temp_file:
            #     temp_file.write(decrypted_content)
            #
            # response = send_file(temp_file_path, as_attachment=True)
            # Use BytesIO to create an in-memory file-like object
            in_memory_file = BytesIO()
            in_memory_file.write(decrypted_content)
            in_memory_file.seek(0)  # Reset file pointer to beginning

            response = send_file(in_memory_file, as_attachment=True,
                                 download_name=temp_file_path)

            return response

    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user'))


# path to restore file
# simply just change temp deleted to not deleted and set restore time limit to None
@blueprint_name.route('/admin_portal/dashboard/<path:username>/files/recoverFile', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def recoverFile(username):
    if username == flask_login.current_user.get_username():
        with bank_app.app_context():
            # check if bucket is empty
            file_id = request.args.get('file_id')
            # retrieve the file to temp delete
            target_file = FileAPI.query.get(file_id)
            # now change the file marker for temp_delete to Deleted
            target_file.set_temp_deleted("Not Deleted")

            target_file.set_restore_time_limit(None)

            db_bank.session.commit()
        return redirect(
            url_for('Bank_Routes.get_admin_files_by_user', username=flask_login.current_user.get_username()))
    else:
        return redirect(url_for('Bank_Routes.authenticated_user'))


@blueprint_name.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@blueprint_name.errorhandler(404)
def handle_404_error(e):
    return redirect(url_for('Bank_Routes.index'))