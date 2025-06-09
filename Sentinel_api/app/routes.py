import base64
import html
import json
import os
import secrets
import smtplib
import ssl
import time
import urllib
from email.message import EmailMessage
from functools import wraps
from io import BytesIO

import flask_login
import pandas
import pyotp as pyotp
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, g, abort, \
    send_from_directory, jsonify, send_file
from flask_login import login_user, login_required, current_user, logout_user
from flask_wtf.csrf import CSRFError, generate_csrf
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import Forbidden

from Sentinel_api.SentinelSuite.secure_storage_center import encrypt_file, decrypt_file, generate_fernet_key, \
    encrypt_with_key, decrypt_with_key, rotate_keys_and_reencrypt, cloudmersivescan
from Sentinel_api.SentinelSuite.streams import add_to_log
from Sentinel_api.app import  app
from Sentinel_api.app.forms import CreateUserForm, CreateLoginForm, EmailVerificationForm, Login2FAForm, \
    ForgetPasswordForm, AddToEvirec, UpdateUserForm, CreateBucketForm, UpdateBucketForm, \
    UploadFileForm, UpdateACLForm, UpdateEvirec, AddFirewallRuleForm, UpdateFirewallRuleForm, LogFileForm, \
    AdminUpdateUserForm
from Sentinel_api.app.models import *
import bcrypt
from sqlalchemy import or_, func, desc
from flask import Blueprint, render_template

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# configure limiter
limiter = Limiter(get_remote_address, app=app)

# setup pyotp
totp = pyotp.TOTP(pyotp.random_base32())

api_keys = {
    'SENTINEL_SUITE_BETA': 'some_user_id',
    # Add more key-user_id pairs as needed
}

blueprint_name = Blueprint('Sentinel_Routes', __name__)
# Define a blueprint with routes that should be exempt from CSRF protection
api_blueprint = Blueprint('Sentinel_API_Routes', __name__)

from Sentinel_api.app import csrf

def create_sentinel_role(data):
    with app.app_context():
        if SentinelRoleModel.query.filter_by(rolename=data['rolename']).first() is None:
            new_role = SentinelRoleModel(rolename=data['rolename'])
            db.session.add(new_role)
            new_role.set_employee_permission(data["employee"])
            new_role.set_developer_permission(data['developer'])
            new_role.set_superadmin_permission(data['superadmin'])
            db.session.commit()

# files after retention period should be deleted

def permanently_delete_file():
    with app.app_context():
        all_files = File.query.all()
        for file in all_files:
            if file.time_to_delete == None:
                pass
            elif datetime.datetime.now() > file.time_to_delete:
                db.session.delete(file)
        db.session.commit()
    return "Files deleted cron job"



def start_retention_period_for_files():
    with app.app_context():
        all_files = File.query.all()
        for file in all_files:
            if file.restore_time_limit == None:
                pass
            elif file.restore_time_limit > datetime.datetime.now():
                file.set_permanently_deleted("Permanently Deleted")
                retention_period = file.bucket.lifecycle_policy.days_to_permanent_deletion
                delete_date = datetime.datetime.now() + timedelta(days=retention_period)
                file.set_time_to_delete(delete_date)
        db.session.commit()
    return "Files set for permanent deletion cron job"



# do key rotation
key_rotation_interval = 30



# @blueprint_name.before_request
# def before_request():
#     with app.app_context():
#         blocked_ips = [entry.block_ip for entry in FirewallBlockList.query.all()]
#         print(request.environ['REMOTE_ADDR'])
#         if request.remote_addr in blocked_ips:
#             print("Access Denied")
#             raise Forbidden()
#         else:
#             pass


@blueprint_name.route('/')
def index():
    # need to generate the default roles that should always exist
    superadmin_data = {"rolename": "SUPER_ADMIN",
                       "superadmin": "Authorized",
                       "developer": "Unauthorized",
                       "employee": "Unauthorized"}

    developer_data = {"rolename": "DEVELOPER",
                     "superadmin": "Unauthorized",
                     "developer": "Authorized",
                       "employee": "Authorized"}

    employee_data = {"rolename": "EMPLOYEE",
                 "superadmin": "Unauthorized",
                 "developer": "Unauthorized",
                "employee": "Authorized"}

    create_sentinel_role(superadmin_data)
    create_sentinel_role(developer_data)
    create_sentinel_role(employee_data)

    rotate_keys_and_reencrypt(key_rotation_interval)

    start_retention_period_for_files()

    permanently_delete_file()

    return render_template('index.html')


@blueprint_name.route('/login', methods=['GET', 'POST'])
@limiter.limit("100/hour", methods=["POST"])
def login():
    # init login form

    # need to add 2 lines for csrf
    csrf.protect()
    session['_csrf_token'] = generate_csrf()

    createloginform = CreateLoginForm(request.form)

    # need to add 2 lines for csrf
    csrf_token = generate_csrf()
    createloginform.csrf_token = csrf_token

    if current_user.is_authenticated:
        return redirect(url_for("Sentinel_Routes.authenticated_user", username=current_user.get_username()))

    if request.method == "POST":
        # Get CSRF token from form submission
        csrf_token_form = request.form.get('csrf_token')

        # Get CSRF token from session
        csrf_token_session = session.get('_csrf_token')

        # Print out CSRF tokens for debugging
        print("CSRF token from form:", csrf_token_form)
        print("CSRF token from session:", csrf_token_session)

        email = html.escape(createloginform.email.data)
        password = createloginform.password.data.encode('utf-8')
        check_user_exist = SentinelUserModel.query.filter_by(email=email).first()
        if not check_user_exist:
            flash("That email does not exist, please try again or register for an account")
            return redirect(url_for('Sentinel_Routes.login'))

        if check_user_exist.check_locked_time_done() is False:
            flash("Account is locked")
            return redirect(url_for('Sentinel_Routes.login'))

        if check_user_exist and bcrypt.checkpw(password,
                                               check_user_exist.get_password().encode()) and check_user_exist.check_locked_time_done():
            check_user_exist.reset_failed_login_count()
            db.session.commit()
            if check_user_exist.get_enable_2fa_email() == "Not Enabled":
                if createloginform.rememberme.data == "Enabled":
                    login_user(check_user_exist, remember=True)
                else:
                    login_user(check_user_exist)
                db.session.commit()
            else:
                return redirect(
                    url_for('Sentinel_Routes.confirm_2fa_login', user_id=check_user_exist.get_id(), email=check_user_exist.get_email(), rememberme=createloginform.rememberme.data))

            return redirect(url_for('Sentinel_Routes.authenticated_user', username=check_user_exist.get_username()))
        else:
            flash("Invalid Credentials")
            check_user_exist.failed_login_increment()
            db.session.commit()
            print("Incremented")
    else:
        print()

    return render_template("login.html", form=createloginform, logged_in=current_user.is_authenticated)

# forget password section
@blueprint_name.route('/forgetpassword', methods=['GET', 'POST'])
def forget_password():
    email_verification_form = EmailVerificationForm(request.form)

    if request.method == "POST" and email_verification_form.validate():
        email = email_verification_form.email.data
        print(email)
        user_to_update = SentinelUserModel.query.filter_by(email=email).first()

        # set serverside verification token
        token = secrets.token_urlsafe(32)
        user_to_update.set_forget_password_token(token)

        otp_token = totp.now()
        user_to_update.set_otp_token(otp_token)

        db.session.commit()

        return redirect(url_for('Sentinel_Routes.send_reset_link', email=email, random_code=otp_token, token=token))

    return render_template('email_verification.html', form=email_verification_form)

# forget password section
@blueprint_name.route('/api/IAM_forget_password', methods=['GET', 'POST'])
def iam_forget_password():
    email_verification_form = EmailVerificationForm(request.form)

    if request.method == "POST" and email_verification_form.validate():
        email = email_verification_form.email.data
        user_to_update = SentinelIAMUserModel.query.filter_by(email=email).first()

        # set serverside verification token
        token = secrets.token_urlsafe(32)
        user_to_update.set_forget_password_token(token)

        otp_token = totp.now()
        user_to_update.set_otp_token(otp_token)

        db.session.commit()

        return redirect(url_for('Sentinel_Routes.iam_send_reset_link', email=email, random_code=otp_token, token=token))

    return render_template('email_verification.html', form=email_verification_form)

# first verification is the email
# second verfication is a code sent to user in email to enter in reset password
# third verification is the server side verification using the forget password token to check if url arg is same
def login_2fa_email(email_to_send_to):
    email = email_to_send_to
    email_sender = 'medusapc123@gmail.com'
    email_receiver = str(email)
    app_password = "hourgtepdumwweou"

    # last for 30 seconds
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
    login_2fa_email(email_to_send_to=email_received)

    if request.method == "POST" and confirmloginform.validate_on_submit():
        otp_submitted = confirmloginform.OTP.data
        if totp.verify(otp_submitted):
            userid = request.args.get('user_id')
            get_user = db.session.execute(db.Select(SentinelUserModel).filter_by(id=userid)).scalar_one()
            if rememberme == "Enabled":
                login_user(get_user, remember=True)
            else:
                login_user(get_user)
            return redirect(url_for('Sentinel_Routes.authenticated_user', username=get_user.get_username()))
        else:
            flash("Expired OTP token")
            return redirect(url_for('Sentinel_Routes.login'))

    return render_template('login_2fa_form.html', form=confirmloginform)

@blueprint_name.route('/send_reset_link', methods=['GET', 'POST'])
def send_reset_link():
    email = request.args.get('email')
    token = request.args.get('token')
    otp = request.args.get('random_code')
    email_sender = 'medusapc123@gmail.com'
    email_receiver = str(email)
    app_password = "hourgtepdumwweou"

    email_encoded = urllib.parse.quote_plus(email)

    subject = "Below is the password recovery link for Medusa PC"
    body = f"""
    Your OTP is {otp}
    Click on this link to reset your password: https://localhost:6500/reset-password/{token}/{email_encoded}
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

@blueprint_name.route('/api/iam_send_reset_link', methods=['GET', 'POST'])
def iam_send_reset_link():
    email = request.args.get('email')
    token = request.args.get('token')
    otp = request.args.get('random_code')
    email_sender = 'medusapc123@gmail.com'
    email_receiver = str(email)
    app_password = "hourgtepdumwweou"

    email_encoded = urllib.parse.quote_plus(email)

    subject = "Below is the password recovery link for Medusa PC"
    body = f"""
    Your OTP is {otp}
    Click on this link to reset your password: https://localhost:6500/iam-reset-password/{token}/{email_encoded}
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

@blueprint_name.route('/reset-password/<path:token>/<path:email>', methods=['GET', 'POST'])
def reset_password(token, email):
    user_token = token
    email = email
    current_user_to_reset_password = SentinelUserModel.query.filter_by(email=email).first()

    if user_token != current_user_to_reset_password.get_forget_password_token():
        return redirect(url_for('Sentinel_Routes.index'))

    forgetpasswordform = ForgetPasswordForm(request.form)
    if request.method == "POST" and forgetpasswordform.validate():
        while True:
            new_password = forgetpasswordform.password.data
            new_password_confirm = forgetpasswordform.confirm_password.data
            user_input_OTP = forgetpasswordform.OTP.data
            if new_password == new_password_confirm or user_input_OTP != current_user_to_reset_password.get_OTP_token():
                break
            else:
                forgetpasswordform = ForgetPasswordForm(request.form)

        new_password = new_password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        current_user_to_reset_password.set_password(pwd_hash)
        db.session.commit()
        # login_user(current_user_to_reset_password)
        # return redirect(url_for('get_dashboard', username=current_user_to_reset_password.get_username(),
        #                         logged_in=current_user.is_authenticated))
        return redirect(url_for('Sentinel_Routes.login'))

    return render_template("forgot_password_form.html", form=forgetpasswordform)

@blueprint_name.route('/iam-reset-password/<path:token>/<path:email>', methods=['GET', 'POST'])
def iam_reset_password(token, email):
    user_token = token
    email = email
    current_user_to_reset_password = SentinelIAMUserModel.query.filter_by(email=email).first()

    if user_token != current_user_to_reset_password.get_forget_password_token():
        return jsonify({'message': 'Invalid credentials'}), 401

    forgetpasswordform = ForgetPasswordForm(request.form)
    if request.method == "POST" and forgetpasswordform.validate():
        while True:
            new_password = forgetpasswordform.password.data
            new_password_confirm = forgetpasswordform.confirm_password.data
            user_input_OTP = forgetpasswordform.OTP.data
            if new_password == new_password_confirm or user_input_OTP != current_user_to_reset_password.get_OTP_token():
                break
            else:
                forgetpasswordform = ForgetPasswordForm(request.form)

        new_password = new_password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        current_user_to_reset_password.set_password(pwd_hash)
        db.session.commit()
        # login_user(current_user_to_reset_password)
        # return redirect(url_for('get_dashboard', username=current_user_to_reset_password.get_username(),
        #                         logged_in=current_user.is_authenticated))
        return jsonify({'message': 'Success'}), 200

    return render_template("forgot_password_form.html", form=forgetpasswordform)

# by default is employee
# developer role can only be given by the superadmin
@blueprint_name.route("/registerUser", methods=["GET", "POST"])
def registerUser():
    createuserform = CreateUserForm(request.form)
    if request.method == "POST" and createuserform.validate():
        # encryption of password

        # escape html to prevent xss
        password = html.escape(createuserform.password.data)
        password = password.encode('utf-8')
        # b64pwd = b64encode(SHA256.new(password).digest())
        # bcrypt_hash = bcrypt(b64pwd,12)
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = html.escape(createuserform.username.data)
        email = html.escape(createuserform.email.data)
        phone = html.escape(createuserform.phone.data)

        check_user_exist = SentinelUserModel.query.filter_by(email=email).first()
        check_username_exist = SentinelUserModel.query.filter_by(username=username).first()
        if check_user_exist is None and check_username_exist is None:
            new_user = SentinelUserModel(
                username=username,
                email=email,
                phone=phone,
                password=pwd_hash,
                role="EMPLOYEE")
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=False)
            return redirect(url_for("Sentinel_Routes.authenticated_user", username=current_user.get_username()))
    return render_template("registerUser.html", form=createuserform, logged_in=current_user.is_authenticated)

@blueprint_name.route('/logout')
@login_required
def logout():
    if not (
            current_user.is_authenticated):
        return redirect(url_for('Sentinel_Routes.index'))
    user_id = current_user.get_id()

    logout_user()

    return redirect(url_for("Sentinel_Routes.index"))

# for testing
@blueprint_name.route('/registerTemporaryUser')
def registerTemporaryUser():
    check_user_exist = SentinelUserModel.query.filter_by(email="UserDemo@email.com").first()
    if not check_user_exist:
        password = "UserDemo"
        password = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = "UserDemo"
        email = "UserDemo@email.com"
        phone = "+65 12345678"
        new_user = SentinelUserModel(
                            username=username,
                            email=email,
                            phone=phone,
                            password=pwd_hash,
                            role="EMPLOYEE",
        )
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('Sentinel_Routes.index'))

@blueprint_name.route('/registerTemporarySuperAdmin')
def registerTemporarySuperAdmin():
    check_user_exist = SentinelUserModel.query.filter_by(email="SuperAdminDemo@email.com").first()
    if not check_user_exist:
        password = "SuperAdminDemo"
        password = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = "SuperAdminDemo"
        email = "SuperAdminDemo@email.com"
        phone = "+65 12345678"
        new_user = SentinelUserModel(
                            username=username,
                            email=email,
                            phone=phone,
                            password=pwd_hash,
                            role="SUPER_ADMIN",
                            )
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('Sentinel_Routes.index'))

@blueprint_name.route('/registerTemporaryDeveloper')
def registerTemporaryDeveloper():
    check_user_exist = SentinelUserModel.query.filter_by(email="DeveloperDemo@email.com").first()
    if not check_user_exist:
        password = "DeveloperDemo"
        password = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = "DeveloperDemo"
        email = "DeveloperDemo@email.com"
        phone = "+65 12345678"
        new_user = SentinelUserModel(
                            username=username,
                            email=email,
                            phone=phone,
                            password=pwd_hash,
                            role="DEVELOPER",
                            )
        db.session.add(new_user)
        new_user.api_key ="SENTINEL_SUITE_BETA"
        db.session.commit()
    return redirect(url_for('Sentinel_Routes.index'))

@blueprint_name.route('/registerTemporaryDeveloper2')
def registerTemporaryDeveloper2():
    check_user_exist = SentinelUserModel.query.filter_by(email="DeveloperDemo2@email.com").first()
    if not check_user_exist:
        password = "DeveloperDemo2"
        password = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = "DeveloperDemo2"
        email = "DeveloperDemo2@email.com"
        phone = "+65 12345678"
        new_user = SentinelUserModel(
                            username=username,
                            email=email,
                            phone=phone,
                            password=pwd_hash,
                            role="DEVELOPER",
                            )
        db.session.add(new_user)
        new_user.api_key ="SENTINEL_SUITE_BETA"
        db.session.commit()
    return redirect(url_for('Sentinel_Routes.index'))

@blueprint_name.route('/deleteUser', methods=['GET', 'POST'])
@login_required
def deleteUser():
    with app.app_context():
        try:
            current_user_to_delete = SentinelUserModel.query.filter_by(email=current_user.get_email()).first()
            all_access_acl = BucketAccess.query.filter_by(email=current_user.get_email()).all()
            all_backup_access_acl = BackupBucketAccess.query.filter_by(email=current_user.get_email()).all()

            for acl in all_backup_access_acl:

                db.session.delete(acl)

            for acl in all_access_acl:
                db.session.delete(acl)
            db.session.commit()

            logout_user()
            db.session.delete(current_user_to_delete)
            db.session.commit()

        except Exception as e:
            print(e)

    return redirect(url_for("Sentinel_Routes.index"))

# rbac stuff
# custom rbac system
def roles_required(*required_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  # unauthorized

            # check if current user role has the relevant permission
            current_user_role = current_user.get_role()

            # get role permissions from rolemodel
            role_permission = db.session.execute(
                db.select(SentinelRoleModel).filter_by(rolename=current_user_role)).scalar_one()

            # check if superadmin because instant access
            if role_permission.get_superadmin_permission() == "Authorized":
                return func(*args, **kwargs)

            # if required role is ADMIN and role_permission has admin_permission
            if "DEVELOPER" in required_roles and role_permission.get_developer_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "EMPLOYEE" in required_roles and role_permission.get_employee_permission() == "Authorized":
                return func(*args, **kwargs)

            abort(403)  # Forbidden

        return wrapper

    return decorator



# router
@blueprint_name.route("/logged_in")
@login_required
def authenticated_user():
    current_user_role = current_user.get_role()

    if db.session.execute(db.select(SentinelRoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_superadmin_permission() == "Authorized":
        return redirect(url_for("Sentinel_Routes.get_admin_dashboard", username=flask_login.current_user.get_username(),
                                ))
    elif db.session.execute(db.select(SentinelRoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_developer_permission() == "Authorized":
        return redirect(url_for("Sentinel_Routes.get_developer_dashboard", username=flask_login.current_user.get_username(),
                                ))
    else:
        return redirect(url_for("Sentinel_Routes.get_dashboard", username=flask_login.current_user.get_username(),
                                ))

# has no route since this is just a confirmation api (note api must exempt csrf because stateless)


@api_blueprint.route('/api/get_all_roles', methods=['POST'])
def get_all_roles():
    if request.method == "POST":
        roles = db.session.execute(db.select(RoleModel)).scalars()
        data = []

        for role in roles:
            if role.get_rolename() != "USER":
                data.append(role.get_rolename())
        response = jsonify({'message': 'return success', 'choices': data})
        return response

# get permissions of role and return as dict
@api_blueprint.route('/api/get_role_permissions', methods=['POST'])
def get_role_permission():
    data = request.json
    permissions = {}
    if request.method == "POST":
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key in api_keys:
            # roles = db.session.execute(db.select(RoleModel).filter_by(rolename=data['role'])).first()
            roles = RoleModel.query.filter_by(rolename=data['role']).first()
            permissions['employee_permission'] = roles.get_employee_permission()
            permissions['user_permission'] = roles.get_user_permission()
            permissions['IT_permission'] = roles.get_IT_permission()
            permissions['manager_permission'] = roles.get_manager_permission()
            permissions['executive_permission'] = roles.get_executive_permission()

        response = jsonify({'message': 'return success', 'permissions': permissions})
        return response

from Sentinel_api.SentinelSuite.Sentinel_API_security import *

from functools import wraps
from flask import jsonify



@api_blueprint.route('/IAM_client_login', methods=['POST'])
def iam_client_login():
    # csrf.protect() include this line if you want csrf protect
    combined_data = request.json # Assuming the request contains JSON data
    combined_data = json.loads(combined_data)


    encrypted_data = base64.b64decode(combined_data['data'])
    aad = base64.b64decode(combined_data['aad'])

    print("Data before")
    print(encrypted_data)

    data = decrypt_transmission(encrypted_data, aad)
    print("Data after")
    print(data)

    if request.method == "POST":
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key in api_keys:
            user = SentinelIAMUserModel.query.filter_by(email=data['email']).first()

            if user.check_locked_time_done() is False:
                return jsonify({'message': 'Account locked'}), 410

            if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
                user.reset_failed_login_count()

                db.session.commit()

                user_data = {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'phone': user.phone,
                    'role': user.get_role(),
                    'password': user.get_password(),
                    'enable_2fa': user.get_enable_2fa_email()
                }
                response = jsonify({'message': 'Login successful', 'user': user_data})

                return response

            else:
                user.failed_login_increment()
                db.session.commit()
                return jsonify({'message': 'Invalid Credentials'}), 401



    return jsonify({'message': 'Invalid credentials'}), 401

@api_blueprint.route('/api/IAM_client_update_user', methods=['POST'])
def iam_client_update_user():
    data = request.json
    if request.method == "POST":
        user = SentinelIAMUserModel.query.filter_by(email=data['target_email']).first()
        user.set_username(data['username'])
        user.set_email(data['email'])
        user.set_password(data['password'])
        user.set_phone(data['phone'])
        user.set_enable_2fa_email(data['enable_2fa'])
        db.session.commit()
        user_data = {
            'email': user.email,
            'username': user.username
        }
        response = jsonify({'message': 'Login successful', 'user': user_data})
        return response

@api_blueprint.route('/api/IAM_client_update_user_by_admin', methods=['POST'])
def iam_client_update_user_by_admin():
    data = request.json
    if request.method == "POST":
        user = SentinelIAMUserModel.query.filter_by(email=data['target_email']).first()
        user.set_username(data['username'])
        user.set_email(data['email'])
        user.set_password(data['password'])
        user.set_phone(data['phone'])
        db.session.commit()
        user_data = {
            'email': user.email,
            'username': user.username
        }
        response = jsonify({'message': 'Login successful', 'user': user_data})
        return response

@api_blueprint.route('/api/IAM_client_delete_user', methods=['POST'])
def iam_client_delete_user():
    data = request.json
    if request.method == "POST":
        user = SentinelIAMUserModel.query.filter_by(id=data['user']).first()
        db.session.delete(user)
        db.session.commit()
        response = jsonify({'message': 'delete successful'}, 200)
        return response


@api_blueprint.route('/api/IAM_client_retrieve_user', methods=['POST'])
def iam_client_retrieve_user():
    data = request.json
    if request.method == "POST":
        user = SentinelIAMUserModel.query.filter_by(email=data['email']).first()
        user_data = {"email": user.get_email(),
                    "username": user.get_username(),
                    "phone":user.get_phone(),
                    "enable_2fa": user.get_enable_2fa_email()}
        response = jsonify({'message': 'Retrieval successful', 'user': user_data})
        return response

@api_blueprint.route('/api/create_role', methods=['POST'])
def create_role():
    # csrf.protect() include this line if you want csrf protect
    data = request.json  # Assuming the request contains JSON data

    if request.method == "POST":
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key in api_keys:
            with app.app_context():
                if RoleModel.query.filter_by(rolename=data['rolename']).first() is None:
                    new_role = RoleModel(rolename=data['rolename'])
                    db.session.add(new_role)
                    new_role.set_user_permission(data['user_permission'])
                    new_role.set_employee_permission(data['employee_permission'])
                    new_role.set_IT_permission(data['IT_permission'])
                    new_role.set_manager_permission(data['manager_permission'])
                    new_role.set_executive_permission(data['executive_permission'])
                    db.session.commit()
            response = jsonify({'message': 'Role add successful'})
            return response



@api_blueprint.route('/api/get_users_using_api_key', methods=['GET'])
def get_users():
    # csrf.protect() include this line if you want csrf protect
    users_retrieved = {}
    if request.method == "GET":
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key in api_keys:
            with app.app_context():
                users = db.session.execute(db.select(SentinelIAMUserModel).filter_by(app_api_key=api_key)).scalars()
                for user in users:
                    user_data = {
                            'id': user.id,
                            'email': user.email,
                            'username': user.username,
                            'phone': user.phone,
                            'role': user.get_role(),
                            'password': user.get_password()
                    }
                    users_retrieved[user.username] = user_data
            response = jsonify({'message': 'Retrieval successful', 'users': users_retrieved})
            return response




# @blueprint_name.route("/IAM_client_registerUser", methods=["POST"])
# def iam_client_registerUser():
#     data = request.json  # Assuming the request contains JSON data
#     print(data)
#     if request.method == "POST":
#
#         # hashing of password
#         # escape html to prevent xss
#         password = html.escape(data['password'])
#         password = password.encode('utf-8')
#         # b64pwd = b64encode(SHA256.new(password).digest())
#         # bcrypt_hash = bcrypt(b64pwd,12)
#         mySalt = bcrypt.gensalt()
#         pwd_hash = bcrypt.hashpw(password, mySalt)
#         pwd_hash = pwd_hash.decode('utf-8')
#
#         username = html.escape(data['username'])
#         email = html.escape(data["email"])
#
#         check_user_exist = SentinelIAMUserModel.query.filter_by(email=email).first()
#         check_username_exist = SentinelIAMUserModel.query.filter_by(username=username).first()
#         if check_user_exist is None and check_username_exist is None:
#             new_user = SentinelIAMUserModel(
#                                  username=username,
#                                  email=email,
#                                  password=pwd_hash,
#                                  authenticated=True)
#             db.session.add(new_user)
#             db.session.commit()
#
#             return jsonify({'message': 'Login successful', 'user': {'username': new_user.username, 'email': new_user.email}})
#
#
#
#     return jsonify({'message': 'Invalid email or username'}), 401

def iam_client_registerUser_SDK(data):
    # hashing of password
    # escape html to prevent xss
    password = html.escape(data['password'])
    password = password.encode('utf-8')
    # b64pwd = b64encode(SHA256.new(password).digest())
    # bcrypt_hash = bcrypt(b64pwd,12)
    mySalt = bcrypt.gensalt()
    pwd_hash = bcrypt.hashpw(password, mySalt)
    pwd_hash = pwd_hash.decode('utf-8')

    username = html.escape(data['username'])
    email = html.escape(data["email"])

    phone = html.escape(data['phone'])

    role = html.escape(data['role'])

    app_api_key = html.escape(data['app_api_key'])

    with app.app_context():
        check_user_exist = SentinelIAMUserModel.query.filter_by(email=email).first()
        check_username_exist = SentinelIAMUserModel.query.filter_by(username=username).first()
        if check_user_exist is None and check_username_exist is None:
            new_user = SentinelIAMUserModel(
                                 username=username,
                                 email=email,
                                phone=phone,
                                 password=pwd_hash,
                                 role=role,
            app_api_key=app_api_key)
            db.session.add(new_user)
            db.session.commit()
            user_data = {
                'id': new_user.id,
                'email': new_user.email,
                'username': new_user.username,
                'phone': new_user.phone,
                'role': new_user.get_role(),
                'password': new_user.get_password()
            }

            return user_data



    return 401





# below to test auth
# @blueprint_name.route('/sentinel_api_portal/<path:username>')
# @login_required
# def sentinel_api_portal(username):
#     return f'Hello, {username}! Welcome to the Sentinel API Portal.'

@blueprint_name.route('/uwiebciwepciewpciowpeicnpownecownoc/export')
@login_required
def export_data():
    logs = LogsModel.query.filter_by(app_api_key=flask_login.current_user.api_key).all()
    # convert to pandas dataframe
    data = [(log.get_log_id(), log.get_user_id(), log.get_classification(), log.get_priority(), log.get_time(),
             log.get_target(), log.get_details()) for log in logs]
    df = pandas.DataFrame(data, columns=['Log_id', 'User_id', 'Class', 'Priority', 'Time', 'Target', 'Details'])

    # export the dataframe to an excel file
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    excel_file = f'{current_date}.xlsx'

    # export the dataframe to excel file
    file_path = os.path.join('../static/log_reports', excel_file)
    df.to_excel(file_path, index=False)

    return redirect(url_for('Sentinel_Routes.get_developer_dashboard', username=flask_login.current_user.get_username(),
                            logged_in=flask_login.current_user.is_authenticated,
                            ))

@blueprint_name.route('/static/log_reports', methods=['GET', 'POST'])
def serve_log_file():
    logform = LogFileForm(request.form)
    filename = logform.log_file.data
    print("Path:", os.path.join(os.getcwd(), '../static/log_reports', filename))
    return send_file(os.path.join(os.getcwd(), '../static/log_reports', filename), as_attachment=True)

@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def userProfile_developer(username):
    updateuserform = UpdateUserForm(request.form)
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

            with app.app_context():
                current_user_to_update = SentinelUserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
                current_user_to_update.set_username(new_username)
                current_user_to_update.set_email(new_email)
                current_user_to_update.set_phone(new_phone)
                current_user_to_update.set_password(pwd_hash)
                current_user_to_update.set_enable_2fa_email(enable_2fa)
                db.session.commit()

                login_user(current_user_to_update, remember=True)
                return redirect(url_for('Sentinel_Routes.authenticated_user', username=current_user_to_update.get_username(),
                                        logged_in=flask_login.current_user.is_authenticated,
                                        ))
        else:
            return redirect(url_for('Sentinel_Routes.userProfile_developer', username=flask_login.current_user.get_username(),
                                    ))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            current_user_to_update = SentinelUserModel.query.filter_by(email=flask_login.current_user.email).first()
            updateuserform.username.data = current_user_to_update.get_username()
            updateuserform.email.data = current_user_to_update.get_email()
            updateuserform.phone.data = current_user_to_update.get_phone()
            updateuserform.enable_2fa.data = current_user_to_update.get_enable_2fa_email()
            return render_template("dashboard_admin_user_profile.html", username=username,
                                   form=updateuserform)
        else:
            return redirect(
                url_for('Sentinel_Routes.authenticated_user', username=flask_login.current_user.get_username(),
                        logged_in=flask_login.current_user.is_authenticated,
                        ))

@blueprint_name.route('/sentinel_api_portal/admin/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def userProfile_admin(username):
    updateuserform = UpdateUserForm(request.form)
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

            with app.app_context():
                current_user_to_update = SentinelUserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
                current_user_to_update.set_username(new_username)
                current_user_to_update.set_email(new_email)
                current_user_to_update.set_phone(new_phone)
                current_user_to_update.set_password(pwd_hash)
                current_user_to_update.set_enable_2fa_email(enable_2fa)
                db.session.commit()

                login_user(current_user_to_update, remember=True)
                return redirect(url_for('Sentinel_Routes.authenticated_user', username=current_user_to_update.get_username(),
                                        logged_in=flask_login.current_user.is_authenticated,
                                        ))
        else:
            return redirect(url_for('Sentinel_Routes.userProfile_admin', username=flask_login.current_user.get_username(),
                                    ))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            current_user_to_update = SentinelUserModel.query.filter_by(email=flask_login.current_user.email).first()
            updateuserform.username.data = current_user_to_update.get_username()
            updateuserform.email.data = current_user_to_update.get_email()
            updateuserform.phone.data = current_user_to_update.get_phone()
            updateuserform.enable_2fa.data = current_user_to_update.get_enable_2fa_email()
            return render_template("dashboard_superadmin_user_profile.html", username=username,
                                   form=updateuserform)
        else:
            return redirect(
                url_for('Sentinel_Routes.authenticated_user', username=flask_login.current_user.get_username(),
                        logged_in=flask_login.current_user.is_authenticated,
                        ))


# can only use the shared file service
@blueprint_name.route('/sentinel_api_portal/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_dashboard(username):
    if username == flask_login.current_user.get_username():
        return render_template("dashboard_user.html", username=username,)


@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('DEVELOPER')
def get_developer_dashboard(username):
    if username == flask_login.current_user.get_username():
        logform = LogFileForm(request.form)

        current_user = username
        # Retrieve filter values from request arguments
        start_date = request.args.get('start_date', type=str)
        end_date = request.args.get('end_date', type=str)
        priority = request.args.get('priority', type=str)
        classification = request.args.get('classification', type=str)
        log_id = request.args.get('log_id', type=str)
        user_id = request.args.get('user_id', type=str)
        target = request.args.get('target', type=str)
        detail = request.args.get('detail', type=str)
        sourceip = request.args.get('sourceip', type=str)

        query = LogsModel.query

        # filter logs based on provided filters
        app_api_key = flask_login.current_user.get_api_key()
        print(app_api_key)
        query = query.filter(LogsModel.app_api_key == str(app_api_key).strip())

        if start_date and end_date:
            query = query.filter(LogsModel.time.between(start_date, end_date))

        if priority:
            query = query.filter(LogsModel.priority == priority)

        if classification is not None and classification != 'None':
            # matches input at beginning, middle or end
            query = query.filter(
                or_(LogsModel.classification.ilike(f"%{classification}%"),
                    LogsModel.classification.ilike(f"{classification}%"),
                    LogsModel.classification.ilike(f"%{classification}"))
            )

        if log_id is not None and log_id != 'None':
            query = query.filter(
                or_(LogsModel.log_id.ilike(f"%{log_id}%"),
                    LogsModel.log_id.ilike(f"{log_id}%"),
                    LogsModel.log_id.ilike(f"%{log_id}"))
            )

        if user_id is not None and user_id != 'None':
            query = query.filter(
                or_(LogsModel.user_id.ilike(f"%{user_id}%"),
                    LogsModel.user_id.ilike(f"{user_id}%"),
                    LogsModel.user_id.ilike(f"%{user_id}"))
            )

        if target is not None and target != 'None':
            query = query.filter(
                or_(LogsModel.target.ilike(f"%{target}%"),
                    LogsModel.target.ilike(f"{target}%"),
                    LogsModel.target.ilike(f"%{target}"))
            )

        if detail is not None and detail != 'None':
            query = query.filter(
                or_(LogsModel.details.ilike(f"%{detail}%"),
                    LogsModel.details.ilike(f"{detail}%"),
                    LogsModel.details.ilike(f"%{detail}"))
            )

        if sourceip is not None and sourceip != 'None':
            query = query.filter(
                or_(LogsModel.source_ip.ilike(f"%{sourceip}%"),
                    LogsModel.source_ip.ilike(f"{sourceip}%"),
                    LogsModel.source_ip.ilike(f"%{sourceip}"))
            )
        print(query)
        logsmodel = query.order_by(LogsModel.time).all()
        logsmodel = sorted(logsmodel, key=lambda x: x.time)

        original_logs_model = LogsModel.query.all()
        original_logs_model = sorted(original_logs_model, key=lambda x: x.time)

        total_logs_count = len(logsmodel)

        if total_logs_count <= 0:
            logsmodel = original_logs_model

        # Assuming you want to get the count of each distinct value in the "column_name" column
        result = db.session.query(LogsModel.classification, func.count(LogsModel.classification)).group_by(
            LogsModel.classification).all()

        priority_result = db.session.query(LogsModel.priority, func.count(LogsModel.priority)).group_by(
            LogsModel.priority).all()

        date_results = db.session.query(func.date(LogsModel.time),
                                        func.count(func.date(LogsModel.time))).group_by(func.date(LogsModel.time)).all()

        date_results = sorted(date_results, key=lambda x: x[0])

        count_list = [(value, count) for value, count in result]

        priority_list = [(value, count) for value, count in priority_result]

        date_list = [(value.strftime("%Y-%m-%d"), count) for value, count in date_results]

        logs_classification_list = []
        logs_count = []

        logs_priority_list = []
        logs_priority_count = []

        logs_date_list = []
        logs_date_count = []

        for count_tuple in count_list:
            logs_classification_list.append(count_tuple[0])
            logs_count.append(count_tuple[1])

        for count_tuple in priority_list:
            logs_priority_list.append(count_tuple[0])
            logs_priority_count.append(count_tuple[1])

        # i need a list of dates for the labels
        for tup in date_list:
            logs_date_list.append(tup[0])
            logs_date_count.append(tup[1])

        filename_list = os.listdir("../static/log_reports")

        logform.log_file.choices = [(filename, filename) for filename in filename_list]

        createevirecform = AddToEvirec(request.form)

        page = request.args.get("page", 1, type=int)
        per_page = 10  # display 10 logs per page

        pagination_logs = query.paginate(page=page,
                                         per_page=per_page)  # i want to paginate the logs model to 10 per page and order by time

        # since i want the start_date to reset
        start_date = original_logs_model[0].get_time()
        end_date = original_logs_model[-1].get_time()

        return render_template("dashboard_developer.html",  username=username,
                               logs_classes=logs_classification_list, logs_count=logs_count,
                               logs_priority=logs_priority_list, logs_priority_count=logs_priority_count,
                               logs_model=logsmodel, log_files=filename_list,
                               logs_dates=logs_date_list, logs_date_count=logs_date_count,
                               createevirec=createevirecform, logs_pages=pagination_logs,
                               start_date=start_date, end_date=end_date, priority=priority,
                               classification=classification, log_id=log_id, user_id=user_id, target=target,
                               detail=detail,
                               sourceip=sourceip,
                               total_logs_count=total_logs_count,
                               original_logs_model=original_logs_model,
                               logform=logform)
    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user', username=flask_login.current_user.get_username()))

@blueprint_name.route('/sentinel_api_portal/admin/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def get_admin_dashboard(username):
    if username == flask_login.current_user.get_username():
        return render_template("dashboard_admin.html", username=username,)


def create_new_evirec_path_helper(logidlist, pathname, desc):
    with app.app_context():
        for id in logidlist:
            evirec_item = EVIRECModel(logid=id, pathname=pathname, description=desc)
            db.session.add(evirec_item)

        db.session.commit()

def get_evirec_log_id_path_list_helper(pathname):
    with app.app_context():
        id_list = []
        list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=pathname)).scalars()
        for item in list_of_pathname_evirec:
            id_list.append(item.get_log_id())
        return id_list


def update_evirec_path_helper(logidlist, pathname, desc):
    current_id = get_evirec_log_id_path_list_helper(pathname)
    with app.app_context():
        for id in logidlist:
            if id not in current_id:
                evirec_item = EVIRECModel(logid=id, pathname=pathname, description=desc)
                db.session.add(evirec_item)
            else:
                evirec_it = db.session.execute(db.Select(EVIRECModel).filter_by(evirec_id=id)).scalar_one()
                evirec_it.set_time_updated(datetime.datetime.now())
        db.session.commit()

def update_evirec_path_name_helper(old_path, new_pathname):
    with app.app_context():
        list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=old_path)).scalars()
        for entry in list_of_pathname_evirec:
            entry.set_path_name(new_pathname)
            entry.set_time_updated(datetime.datetime.now())
            add_to_log(classification='JOB',
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"Developer with user id of {flask_login.current_user.get_id()} updated EVIREC PATH of name {new_pathname}.",
                       app_api_key=current_user.get_api_key(),
                       user_id=current_user.get_id())
        db.session.commit()

def update_evirec_path_name_and_description_helper(old_path, new_pathname, new_description):
    with app.app_context():
        list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=old_path)).scalars()
        for entry in list_of_pathname_evirec:
            entry.set_path_name(new_pathname)
            entry.set_description(new_description)
            entry.set_time_updated(datetime.datetime.now())
            add_to_log(classification='JOB',
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"Developer with user id of {flask_login.current_user.get_id()} updated EVIREC PATH of name {new_pathname}.",
            app_api_key = current_user.get_api_key(),
                          user_id = current_user.get_id()
            )
        db.session.commit()

def delete_evirec_path_helper(pathName):
    with app.app_context():
        list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=pathName)).scalars()
        for entry in list_of_pathname_evirec:
            db.session.delete(entry)
            add_to_log(classification='JOB',
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"Developer with user id of {flask_login.current_user.get_id()} deleted EVIREC PATH of name {pathName}.",
                       app_api_key=current_user.get_api_key(),
                       user_id=current_user.get_id()
                       )
        db.session.commit()

def delete_evirec_item_helper(evirec_id):
    with app.app_context():
        entry_to_delete = EVIRECModel.query.filter_by(evirec_id=evirec_id).first()
        db.session.delete(entry_to_delete)
        add_to_log(classification='JOB',
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Developer with user id of {flask_login.current_user.get_id()} deleted EVIREC ITEM of id {entry_to_delete.evirec_id}.",
                   app_api_key=current_user.get_api_key(),
                   user_id=current_user.get_id()
                   )
        db.session.commit()


@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/evirec/add_path', methods=['POST'])
@login_required
@roles_required('DEVELOPER')
def add_evirec_path(username):
    log_ids_json = request.form.get('log_ids')

    # this is in the form of a list
    log_ids = json.loads(log_ids_json)
    createevirecform = AddToEvirec(request.form)

    pathname = createevirecform.path_name.data.replace(" ", "")
    description = createevirecform.description.data
    if request.method == "POST":
        # write helper function to get log_ids for each id in LogsModel
        # then add to the EVIREC Model table

        # if path does not exist
        if EVIRECModel.query.filter_by(path_name=pathname).first() is None:
            create_new_evirec_path_helper(log_ids, pathname, description)
        else:
            update_evirec_path_helper(log_ids, pathname=pathname, desc=description)

        # then do the same for product where there are tables
        # then when you click show path it will show a table with logs under there

        # then do the click function to allow deletion of logs from the path

        # also allow deletion of path

        # finally if user decides to use same name, it will update the path instead of creating a new path

        return redirect(url_for("Sentinel_Routes.view_evirec_paths", username=flask_login.current_user.get_username(),
                               ))

@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/evirec', methods=['GET', 'POST'])
@login_required
@roles_required('DEVELOPER')
def view_evirec_paths(username):
    # need to get list of all evirec in log time order
    # evirecmodel = db.session.query(EVIRECModel).join(LogsModel).order_by(LogsModel.time).all()
    updateevirec = UpdateEvirec(request.form)

    evirec_pathname = request.args.get("evirec_pathname")

    # unique rows based on path name
    # i want distince rows based on path name and group by path name
    from sqlalchemy.orm import joinedload
    from sqlalchemy import distinct

    # Assuming session is your SQLAlchemy session
    with app.app_context():

        evirec_model = db.session.query(EVIRECModel).distinct(EVIRECModel.path_name).group_by(EVIRECModel.path_name,
                                                                                              EVIRECModel.evirec_id,
                                                                                              EVIRECModel.log_id).all()
    if request.method == "POST":
        new_path_name = updateevirec.path_name.data
        new_description = updateevirec.description.data
        if new_description == "":
            update_evirec_path_name_helper(old_path=evirec_pathname, new_pathname=new_path_name)
        else:
            update_evirec_path_name_and_description_helper(old_path=evirec_pathname, new_pathname=new_path_name,
                                                           new_description=new_description)

    # needs to have table of evirecs

    return render_template("dashboard_admin_evirec.html", username=flask_login.current_user.get_username(),
                            evirec_model=evirec_model,
                           updateevirec=updateevirec)

@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/evirec/delete_path', methods=['POST'])
@login_required
@roles_required('DEVELOPER')
def delete_evirec_path(username):
    # need to get list of all evirec
    evirec_path = request.args.get("evirec_path")
    # needs to have table of evirecs
    if request.method == "POST":
        delete_evirec_path_helper(pathName=evirec_path)

    return redirect(url_for("Sentinel_Routes.view_evirec_paths", username=flask_login.current_user.get_username(),
                            ))

@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/evirec/delete_path_item', methods=['POST'])
@login_required
@roles_required('DEVELOPER')
def delete_evirec_item(username):
    # need to get list of all evirec
    evirec_id = request.args.get("evirec_id")
    # needs to have table of evirecs

    if request.method == "POST":
        delete_evirec_item_helper(evirec_id=evirec_id)

    return redirect(url_for("Sentinel_Routes.view_evirec_paths", username=flask_login.current_user.get_username(),
                            ))

@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/role_interface', methods=['GET', 'POST'])
@login_required
@roles_required('DEVELOPER')
def get_developer_roles_dashboard(username):
    if username == flask_login.current_user.get_username():
        rolemodel = RoleModel.query.all()

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Developer with user id of {flask_login.current_user.get_id()} accessed role management interface.",
                   app_api_key=current_user.get_api_key(),
                   user_id=current_user.get_id())
        return render_template("dashboard_admin_rolemanage.html", username=username,
                               rolemodel=rolemodel)
    else:
        return redirect(url_for('Sentinel_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))

@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/iamuser_interface', methods=['GET', 'POST'])
@login_required
@roles_required('DEVELOPER')
def get_developer_users_dashboard(username):
    if username == flask_login.current_user.get_username():
        iamusermodel = SentinelIAMUserModel.query.all()

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Developer with user id of {flask_login.current_user.get_id()} accessed role management interface.",
                   app_api_key=current_user.get_api_key(),
                   user_id=current_user.get_id())
        return render_template("dashboard_developer_iamusermanage.html", username=username,
                               iamusermodel=iamusermodel)
    else:
        return redirect(url_for('Sentinel_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))

@blueprint_name.route('/sentinel_api_portal/admin/dashboard/<path:username>/all_users', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def get_superadmin_users_dashboard(username):
    if username == flask_login.current_user.get_username():
        iamusermodel = SentinelUserModel.query.all()
        updateuserform = AdminUpdateUserForm(request.form)

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"SuperAdmin with user id of {flask_login.current_user.get_id()} accessed role management interface.",
                   app_api_key=current_user.get_api_key(),
                   user_id=current_user.get_id())
        return render_template("dashboard_admin_usermanage.html", username=username,
                               usermodel=iamusermodel, updateform=updateuserform)
    else:
        return redirect(url_for('Sentinel_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))

@blueprint_name.route('/sentinel_api_portal/admin/dashboard/<path:username>/all_users/update', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def update_user_admin(username):
    updateuserform = AdminUpdateUserForm(request.form)
    if request.method == "POST" and updateuserform.validate():
        target_email = request.args.get('email')
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data


        new_password = updateuserform.password.data
        new_password = new_password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        with app.app_context():
            current_user_to_update = SentinelUserModel.query.filter_by(
                email=target_email).first()
            current_user_to_update.set_username(new_username)
            current_user_to_update.set_email(new_email)
            current_user_to_update.set_phone(new_phone)
            current_user_to_update.set_password(pwd_hash)
            db.session.commit()

        return redirect(
            url_for("Sentinel_Routes.get_superadmin_users_dashboard", username=flask_login.current_user.get_username()))

@blueprint_name.route('/sentinel_api_portal/admin/dashboard/<path:username>/all_users/delete', methods=['GET', 'POST'])
@login_required
def delete_user_admin(username):
    target_email = request.args.get('email')
    with app.app_context():
        try:
            current_user_to_delete = SentinelUserModel.query.filter_by(email=target_email).first()
            all_access_acl = BucketAccess.query.filter_by(email=target_email).all()
            all_backup_access_acl = BackupBucketAccess.query.filter_by(email=target_email).all()

            for acl in all_backup_access_acl:

                db.session.delete(acl)

            for acl in all_access_acl:
                db.session.delete(acl)
            db.session.commit()

            db.session.delete(current_user_to_delete)
            db.session.commit()

        except Exception as e:
            print(e)

    return redirect(url_for("Sentinel_Routes.get_superadmin_users_dashboard", username=username))

# route to give iam users access to dashboard via federated login
@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/iamuser_interface/give_access', methods=['GET','POST'])
@login_required
@roles_required('DEVELOPER')
def get_IAM_user_developer_access(username):
    if username == flask_login.current_user.get_username():

        if request.method == "POST":
            target_email = request.args.get('email')
            print(request.args.get('email'))
            print("Ready to give iam access")

            with app.app_context():
                # remove any user with that same email
                try:
                    user_to_remove = SentinelUserModel.query.filter_by(email=target_email).first()
                    db.session.delete(user_to_remove)
                    db.session.commit()
                except:
                    pass
                # add the user to the sentinel user model so they can use normal login
                user_to_add = SentinelIAMUserModel.query.filter_by(email=target_email).first()
                new_iam_access_user = SentinelUserModel(
                    username="IAM_"+user_to_add.username,
                    email=user_to_add.email,
                    phone=user_to_add.phone,
                    password=user_to_add.password,
                    role="DEVELOPER",
                )
                db.session.add(new_iam_access_user)
                new_iam_access_user.api_key = flask_login.current_user.api_key
                db.session.commit()

                iam_access_given = SentinelIAMAccessUsers(id=user_to_add.id, email=user_to_add.email, username=user_to_add.username)
                db.session.add(iam_access_given)
                db.session.commit()

            return redirect(url_for('Sentinel_Routes.get_developer_users_dashboard', username=flask_login.current_user.get_username(),
                                    ))

    else:
        return redirect(url_for('Sentinel_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))

# route to revoke iam users access to dashboard via federated login
@blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/iamuser_interface/remove_access', methods=['GET','POST'])
@login_required
@roles_required('DEVELOPER')
def remove_IAM_user_developer_access(username):
    if username == flask_login.current_user.get_username():

        if request.method == "POST":
            target_email = request.args.get('email')
            print(request.args.get('email'))
            print("Ready to remove iam access")

            with app.app_context():
                # remove any user with that same email
                try:
                    user_to_remove = SentinelUserModel.query.filter_by(email=target_email).first()
                    db.session.delete(user_to_remove)
                    db.session.commit()
                except:
                    pass


                iam_access_given = SentinelIAMAccessUsers.query.filter_by(email=target_email).first()
                db.session.delete(iam_access_given)
                db.session.commit()

            return redirect(url_for('Sentinel_Routes.get_developer_users_dashboard', username=flask_login.current_user.get_username(),
                                    ))

    else:
        return redirect(url_for('Sentinel_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                                ))

# @blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/roles/add_role', methods=['GET', 'POST'])
# @login_required
# @roles_required('DEVELOPER')
# def createRole_Developer(username):
#
#     createroleform = CreateRoleForm(request.form)
#
#     if request.method == "POST" and createroleform.validate_on_submit():
#         role_name = createroleform.rolename.data
#         superadmin_permission = createroleform.havesuperadmin_permission.data
#         employee_permission = createroleform.haveemployee_permission.data
#         user_permission = createroleform.haveuser_permission.data
#
#         new_role = RoleModel(rolename=role_name)
#
#         db.session.add(new_role)
#
#         new_role.set_superadmin_permission(superadmin_permission)
#         new_role.set_financeadmin_permission(employee_permission)
#         new_role.set_user_permission(user_permission)
#
#         db.session.commit()
#
#         return redirect(url_for('Sentinel_Routes.get_developer_roles_dashboard', username=username))


# @blueprint_name.route('/sentinel_api_portal/developer/updateRole/<path:username>', methods=['GET', 'POST'])
# @login_required
# @roles_required('DEVELOPER')
# def updateRole_Developer(username):
#     role_id = request.args.get('role_id')
#
#     updateroleform = UpdateRoleForm(request.form)
#
#     if request.method == "POST" and updateroleform.validate_on_submit():
#         rolename = updateroleform.rolename.data
#         superadmin_permission = updateroleform.havesuperadmin_permission.data
#         employeee_permission = updateroleform.haveemployee_permission.data
#         user_permission = updateroleform.haveuser_permission.data
#
#         role_to_update = db.session.execute(db.select(RoleModel).filter_by(id=role_id)).scalar_one()
#
#         role_to_update.set_rolename(rolename)
#         role_to_update.set_superadmin_permission(superadmin_permission)
#         role_to_update.set_financeadmin_permission(employeee_permission)
#         role_to_update.set_user_permission(user_permission)
#
#         db.session.commit()
#
#         return redirect(
#             url_for('Sentinel_Routes.get_developer_roles_dashboard', username=username))
#
#     else:
#         role_update = db.session.execute(db.select(RoleModel).filter_by(id=role_id)).scalar_one()
#
#         updateroleform.rolename.data = role_update.get_rolename()
#         updateroleform.havesuperadmin_permission.data = role_update.get_superadmin_permission()
#         updateroleform.haveemployee_permission.data = role_update.get_employee_permission()
#         updateroleform.haveuser_permission.data = role_update.get_user_permission()
#
#         # updateuserform.password = current_user_to_update.password
#
#         return render_template("updateRole.html", updateform=updateroleform, logged_in=current_user.is_authenticated)
#
#
# @blueprint_name.route('/sentinel_api_portal/developer/dashboard/<path:username>/roles/delete_role', methods=['GET', 'POST'])
# @login_required
# @roles_required('DEVELOPER')
# def deleteRole_Developer(username):
#     role_id = request.args.get('role_id')
#
#     if request.method == "POST":
#         role_to_delete = db.session.execute(db.select(RoleModel).filter_by(id=role_id)).scalar_one()
#
#         db.session.delete(role_to_delete)
#
#         db.session.commit()
#
#         return redirect(
#             url_for('Sentinel_Routes.get_developer_roles_dashboard', username=username))

# this will be devleoepr dashboard to see only their app's logs

# firewall center blocklist
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/firewallManager', methods=['GET', 'POST'])
@login_required
@roles_required('DEVELOPER')
def get_firewall_manager_dashboard(username):
    addRuleForm = AddFirewallRuleForm(request.form)
    updateRuleForm = UpdateFirewallRuleForm(request.form)
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            with app.app_context():
                new_firewall_rule = FirewallBlockList(addRuleForm.ip.data)
                db.session.add(new_firewall_rule)
                db.session.commit()

        all_rules = FirewallBlockList.query.all()
        return render_template("dashboard_firewall_manager.html", username=flask_login.current_user.get_username(),
                                rulesmodel=all_rules, addRuleForm=addRuleForm, updateRuleForm=updateRuleForm)
    return redirect(url_for('Sentinel_Routes.get_dashboard', username=flask_login.current_user.get_username(),
                            ))

# delete firewall rule
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/firewallManager/DeleteFirewallRule', methods=['POST'])
@login_required
@roles_required('DEVELOPER')
def delete_firewall_rule(username):
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            with app.app_context():
                rule_id = request.args.get("rule_id")
                firewall_rule_to_delete = FirewallBlockList.query.filter_by(id=rule_id).first()
                db.session.delete(firewall_rule_to_delete)
                db.session.commit()
            return redirect(url_for("Sentinel_Routes.get_firewall_manager_dashboard", username=flask_login.current_user.get_username()))
    return redirect(
        url_for("Sentinel_Routes.get_firewall_manager_dashboard", username=flask_login.current_user.get_username()))

# update firewall rule
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/firewallManager/UpdateFirewallRule', methods=['POST'])
@login_required
@roles_required('DEVELOPER')
def update_firewall_rule(username):
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            with app.app_context():
                rule_id = request.args.get("rule_id")
                firewall_rule_to_update = FirewallBlockList.query.filter_by(id=rule_id).first()
                new_ip = UpdateFirewallRuleForm(request.form).ip.data
                firewall_rule_to_update.update_ip(new_ip)
                db.session.commit()
            return redirect(url_for("Sentinel_Routes.get_firewall_manager_dashboard", username=flask_login.current_user.get_username()))
    return redirect(
        url_for("Sentinel_Routes.get_firewall_manager_dashboard", username=flask_login.current_user.get_username()))

# secure storage center code
# this path will be view all the buckets available
# there will be both public and private buckets
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_buckets_by_user(username):
    createform = CreateBucketForm(request.form)
    updateform = UpdateBucketForm(request.form)
    updateACLform = UpdateACLForm(request.form)
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
                with app.app_context():
                    bucket_id = request.args.get('bucket_id')
                    new_email = updateACLform.email.data
                    new_access = BucketAccess(bucket_id=bucket_id, email=new_email)
                    db.session.add(new_access)
                    db.session.commit()

        # get all the buckets by user
        buckets = Bucket.query.filter_by(user_id=flask_login.current_user.get_id()).all()

        owned_buckets = []
        for buc in buckets:
            owned_buckets.append(buc.id)

        # i need to get the shared buckets (those not owned by me only)
        shared_bucket_id = []
        shared_buckets = BucketAccess.query.filter_by(email=flask_login.current_user.get_email()).all()
        for bucket in shared_buckets:
            if bucket.bucket_id not in owned_buckets:
                shared_bucket_id.append(bucket.bucket_id)

        shared_buckets_to_show = []
        for buc_id in shared_bucket_id:
            shared_buckets_to_show.append(Bucket.query.filter_by(id=buc_id).first())


        # this page will show in a table what buckets the user created in a table
        # there will be links like the blog table, to update and delete buckets
        # when you click on view bucket, it should show a list of files that is in the bucket and a bucket cannot be deleted
        # until bucket is empty
        return render_template("dashboard_global_buckets.html", username=flask_login.current_user.get_username(),
                               bucketmodel=buckets,
                               updateform=updateform, createform=createform, updateACLform=updateACLform, sharedbucketmodel=shared_buckets_to_show)

# route to see all backup buckets sorted by the bucket name
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_Backup', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_backup_buckets_by_user(username):
    # get all the buckets by user
    buckets = BackupBucket.query.filter_by(user_id=flask_login.current_user.get_id()).order_by(desc(BackupBucket.backup_date), BackupBucket.name).all()
    return render_template("dashboard_global_backup_buckets.html", username=flask_login.current_user.get_username(),
                           bucketmodel=buckets,
                           )

# route to backup a file in a bucket on click
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC/Backup', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def backup_bucket_files(username):
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            with app.app_context():
                # get the specific bucket to backup
                bucket_id = request.args.get('bucket_id')
                target_bucket = Bucket.query.filter_by(id=bucket_id).first()
                target_lifecycle = LifecyclePolicy.query.filter_by(id=target_bucket.lifecycle_policy_id).first()
                target_key = SentinelKMS.query.filter_by(id=target_bucket.sentinel_kms_id).first()
                target_acl = BucketAccess.query.filter_by(bucket_id=target_bucket.id).all()

                # retrieve all attributes of the files in the bucket
                files = File.query.filter_by(bucket_id=bucket_id).all()



                # create backup bucket
                new_backup_bucket = BackupBucket(
                   id="BackupBucket"+str(uuid.uuid4()),
                    bucket_id=target_bucket.id,
                    name=target_bucket.name,
                    user_id=target_bucket.user_id,
                    lifecycle_policy_id=target_bucket.lifecycle_policy_id,
                    sentinel_kms_id=target_bucket.sentinel_kms_id,
                    availability=target_bucket.availability,
                    backup_date = datetime.datetime.now()


                )
                db.session.add(new_backup_bucket)
                db.session.commit()

                # add files to the backup file table
                for file in files:
                    backup_file = BackupFile(id="BackupFile" + str(uuid.uuid4()),
                                             backup_bucket_id=new_backup_bucket.id,
                                             file_id=file.id,
                                             name=file.name,
                                             path=file.path,
                                             encrypted_content=file.encrypted_content,
                                             uploaded_at=file.uploaded_at,
                                             bucket_id=file.bucket_id,
                                             user_id=file.user_id,
                                             temp_deleted=file.temp_deleted,
                                             restore_time_limit=file.restore_time_limit,
                                             time_to_delete=file.time_to_delete,
                                             permanently_deleted=file.permanently_deleted)
                    db.session.add(backup_file)

                db.session.commit()

                # create backup key, acl and lifecycle policy
                new_backup_lifecycle = BackupLifecyclePolicy(
                    backup_bucket_id=new_backup_bucket.id,
                    life_id=target_lifecycle.id,
                    days_to_archive=target_lifecycle.days_to_archive,
                    days_to_permanent_deletion=target_lifecycle.days_to_permanent_deletion
                )

                db.session.add(new_backup_lifecycle)
                db.session.commit()

                new_kms_key = BackupSentinelKMS(
                    backup_bucket_id=new_backup_bucket.id,
                    kms_id=target_key.id,
                    last_date_of_rotation=target_key.last_date_of_rotation,
                    key=target_key.encryption_key,
                    bucket_id=target_bucket.id
                )
                db.session.add(new_kms_key)
                db.session.commit()

                for acl in target_acl:
                    new_acl = BackupBucketAccess(
                        backup_bucket_id=new_backup_bucket.id,
                        acl_id=acl.id,
                        bucket_id=acl.bucket_id,
                        email=acl.email
                    )
                    db.session.add(new_acl)
                db.session.commit()


    return redirect(url_for('Sentinel_Routes.get_backup_buckets_by_user', username=flask_login.current_user.get_username()))

# route to delete a backup a file in a bucket on click
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC/DeleteBackup', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def delete_backup_bucket(username):
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            with app.app_context():
                # get backup id
                backup_id = request.args.get('backup_bucket_id')
                # delete ACL
                acls_to_delete = BackupBucketAccess.query.filter_by(backup_bucket_id=backup_id).all()
                for acl in acls_to_delete:
                    try:
                        db.session.delete(acl)
                    except:
                        pass

                db.session.commit()

                #delete kms
                try:
                    kms_to_delete = BackupSentinelKMS.query.filter_by(backup_bucket_id=backup_id).first()
                    db.session.delete(kms_to_delete)
                    db.session.commit()
                except:
                    pass

                # delete lifecycle policy
                try:
                    lifepol_delete = BackupLifecyclePolicy.query.filter_by(backup_bucket_id=backup_id).first()
                    db.session.delete(lifepol_delete)
                    db.session.commit()
                except:
                    pass

                # delete all backup files
                try:
                    files_delete = BackupFile.query.filter_by(backup_bucket_id=backup_id).all()
                    for file in files_delete:
                        db.session.delete(file)
                    db.session.commit()
                except:
                    pass

                # delete the bucket
                try:
                    backupbucket_delete = BackupBucket.query.filter_by(id=backup_id).first()
                    db.session.delete(backupbucket_delete)
                    db.session.commit()
                except:
                    pass
    return redirect(
        url_for('Sentinel_Routes.get_backup_buckets_by_user', username=flask_login.current_user.get_username()))


# route to backup a file in a bucket on click
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_Backup/Restore', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def restore_bucket_files(username):
    if username == flask_login.current_user.get_username():
        if request.method == "POST":
            with app.app_context():
                backup_bucket_id = request.args.get('backup_bucket_id')
                target_backup_bucket = BackupBucket.query.filter_by(id=backup_bucket_id).first()

                try:
                    # first must clear the current files related to the bucket
                    files_to_clear = File.query.filter_by(bucket_id=target_backup_bucket.bucket_id).all()
                    for file in files_to_clear:
                        db.session.delete(file)
                    db.session.commit()

                    # then delete the bucket
                    bucket_to_clear = Bucket.query.filter_by(id=target_backup_bucket.bucket_id).first()
                    db.session.delete(bucket_to_clear)
                    db.session.commit()

                except:
                    # pass if bucket does not exist
                    pass

                # now use the rows in the backup tables to add back the bucket and files and key
                backup_lifecycle_policy = BackupLifecyclePolicy.query.filter_by(backup_bucket_id=target_backup_bucket.id).first()
                new_lifecycle_policy = LifecyclePolicy(
                    days_to_archive=backup_lifecycle_policy.days_to_archive,
                    days_to_permanent_deletion=backup_lifecycle_policy.days_to_permanent_deletion,
                )

                db.session.add(new_lifecycle_policy)
                db.session.commit()

                # lifecycle policy attached to bucket
                new_bucket = Bucket(name=target_backup_bucket.name,
                                    lifecycle_policy_id=new_lifecycle_policy.id,
                                    user_id=target_backup_bucket.user_id,
                                    availability=target_backup_bucket.availability)

                db.session.add(new_bucket)
                db.session.commit()

                # change the id of the bucket to the original one
                original_id = target_backup_bucket.bucket_id
                new_bucket.id = original_id
                db.session.commit()

                # need to create the kms key associated with the bucket
                backup_key = BackupSentinelKMS.query.filter_by(
                    backup_bucket_id=target_backup_bucket.id).first()
                new_key = SentinelKMS(key=backup_key.encryption_key,
                                      bucket_id=new_bucket.id)

                db.session.add(new_key)
                db.session.commit()
                new_bucket.set_sentinel_kms_id(new_key.id)

                db.session.commit()

                if target_backup_bucket.availability == "Public":
                    backup_acls = BackupBucketAccess.query.filter_by(
                        backup_bucket_id=target_backup_bucket.id).all()
                    for acl in backup_acls:
                        new_access = BucketAccess(bucket_id=new_bucket.id, email=acl.email)
                        db.session.add(new_access)
                    db.session.commit()

                # now to upload the rest of the files
                backup_files = BackupFile.query.filter_by(
                    backup_bucket_id=target_backup_bucket.id).all()
                for file in backup_files:
                    restored_file = File(
                    id=file.id,
                    name=file.name,
                                encrypted_content=file.encrypted_content,
                                bucket_id=new_bucket.id,
                                user_id=file.user_id)
                    db.session.add(restored_file)
                db.session.commit()

        return redirect(
            url_for('Sentinel_Routes.get_buckets_by_user', username=flask_login.current_user.get_username()))



@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC/delete_email_item', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def delete_email_item(username):
    acl_id = request.args.get('acl_id')
    if request.method == "POST":
        with app.app_context():
            acl_to_delete = BucketAccess.query.filter_by(id=acl_id).first()
            db.session.delete(acl_to_delete)
            db.session.commit()
    return redirect(url_for('Sentinel_Routes.get_buckets_by_user', username=flask_login.current_user.get_username()))

# this second path will handle creation of buckets
# you will create a lifecycle policy as well
# first you save the file
# then you delete the file
# it wont immediately remove the file but hide it first and a button in the file dashbaord is where you can recover it
# then the file will be archived for 30 days
# after archival period of 30 days, there goes permanent deletion
# this will determine
# days to archive: days to hide file for, and once days to archive is up, file is deleted
# days to permanent deletion means
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC/createBucket', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def createBucket(username):
    if username == flask_login.current_user.get_username():
        createform = CreateBucketForm(request.form)
        name = createform.name.data
        days_to_archive = createform.days_to_archive.data
        days_to_permanent_deletion = createform.days_to_permanent_deletion.data
        availability = createform.availability.data

        with app.app_context():
            new_lifecycle_policy = LifecyclePolicy(
                                days_to_archive=days_to_archive,
                                days_to_permanent_deletion=days_to_permanent_deletion,
                                )

            db.session.add(new_lifecycle_policy)
            db.session.commit()

            # lifecycle policy attached to bucket
            new_bucket = Bucket(name=name,
                                lifecycle_policy_id=new_lifecycle_policy.id,
                                user_id=flask_login.current_user.get_id(),
                                availability=availability)

            db.session.add(new_bucket)
            db.session.commit()

            # need to create the kms key associated with the bucket
            new_key = SentinelKMS(key=generate_fernet_key(),
                                  bucket_id=new_bucket.id)



            db.session.add(new_key)
            db.session.commit()
            new_bucket.set_sentinel_kms_id(new_key.id)

            db.session.commit()

            if availability == "Public":
                new_access = BucketAccess(bucket_id=new_bucket.id, email=flask_login.current_user.get_email())
                db.session.add(new_access)
                db.session.commit()



        return redirect(url_for('Sentinel_Routes.get_buckets_by_user', username=flask_login.current_user.get_username()))
    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user'))


# @blueprint_name.route('/api/createBucketAPI', methods=['POST'])
# def createBucketAPI(username):
#     # csrf.protect() include this line if you want csrf protect
#     data = request.json  # Assuming the request contains JSON data
#
#     if request.method == "POST":
#         api_key = request.headers.get('X-API-Key')
#         if api_key and api_key in api_keys:
#             with app.app_context():
#                 new_lifecycle_policy = LifecyclePolicyAPI(
#                     days_to_archive=90,
#                     days_to_permanent_deletion=180,
#                 )
#
#                 db.session.add(new_lifecycle_policy)
#                 db.session.commit()
#
#                 # lifecycle policy attached to bucket
#                 new_bucket = BucketAPI(name=data["name"],
#                                     lifecycle_policy_id=new_lifecycle_policy.id,
#                                     api_key=data["APIKEY"],)
#
#                 db.session.add(new_bucket)
#                 db.session.commit()
#
#                 # need to create the kms key associated with the bucket
#                 new_key = SentinelKMSAPI(key=generate_fernet_key(),
#                                       bucket_id=new_bucket.id)
#
#                 db.session.add(new_key)
#                 db.session.commit()
#                 new_bucket.set_sentinel_kms_id(new_key.id)
#
#                 db.session.commit()
#             response = jsonify({'message': 'Bucket add successful'})
#             return response
#
# @blueprint_name.route('/api/verifyBucketAPI', methods=['POST'])
# def verifyBucketAPI(username):
#     data = request.json  # Assuming the request contains JSON data
#
#     if request.method == "POST":
#         api_key = request.headers.get('X-API-Key')
#         if api_key and api_key in api_keys:
#             with app.app_context():
#                 if BucketAPI.query.filter_by(name=data['name']):
#                     response = jsonify({'message': 'Bucket exists'})
#                 else:
#                     response = jsonify({'message': 'Bucket does not exist'})
#
#             return response
#
# @blueprint_name.route('/api/uploadFileToBucket', methods=['POST'])
# def upload_file_to_bucket_api(username):
#     data = request.json  # Assuming the request contains JSON data
#
#     uploaded_file = data['file']
#
#     bucket_id = data['bucket_id']
#     if request.method == "POST":
#         api_key = request.headers.get('X-API-Key')
#         if api_key and api_key in api_keys:
#             with app.app_context():
#                 target_bucket = BucketAPI.query.filter_by(id=bucket_id).first()
#                 target_bucket_key = target_bucket.sentinel_kms.get_key()
#
#                 # retrieve key from associated bucket
#                 encrypted_content = encrypt_with_key(key=target_bucket_key, data=uploaded_file.read())
#                 new_file = FileAPI(
#                     id="FILEAPI"+str(uuid.uuid4()),
#                     name=uploaded_file.filename,
#                                 encrypted_content=encrypted_content,
#                                 bucket_id=target_bucket.id,
#                                 user_id=data['user_id'])
#                 db.session.add(new_file)
#                 db.session.commit()
#                 response = jsonify({'message': 'File uploaded'})
#
#                 return response




@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC/deleteBucket', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def deleteBucket(username):
    if username == flask_login.current_user.get_username():
        # check if bucket is empty
        bucket_id = request.args.get('bucket_id')
        with app.app_context():
            bucket = Bucket.query.get(bucket_id)
            if bucket.files.count() == 0:
                # then proceed to delete the bucket, policy and key associated with it
                db.session.delete(bucket)
                db.session.commit()
        return redirect(
            url_for('Sentinel_Routes.get_buckets_by_user', username=flask_login.current_user.get_username()))
    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user'))

# this route below will let the user see all files he or she uploaded
# rule is if bucket is temp deleted, the download file button will be the restore button
# if the bucket is not temp deleted, the download file button will be shown
# if the file is permanently deleted, file will not be shown in the table
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_files', methods=['GET', 'POST'])
@login_required
@roles_required('EMPLOYEE')
def get_files_by_user(username):
    uploadform = UploadFileForm(request.form)
    uploadform.bucket.choices = [(str(bucket.id), bucket.name) for bucket in Bucket.query.filter_by(user_id=flask_login.current_user.get_id()).all()]
    if username == flask_login.current_user.get_username():
        # get all the buckets by user
        files = File.query.filter_by(user_id=flask_login.current_user.get_id()).all()

        # get shared files
        # i need to get the shared buckets (those not owned by me only)
        # get all the buckets by user
        buckets = Bucket.query.filter_by(user_id=flask_login.current_user.get_id()).all()

        owned_buckets = []
        for buc in buckets:
            owned_buckets.append(buc.id)

        shared_bucket_id = []
        shared_buckets = BucketAccess.query.filter_by(email=flask_login.current_user.get_email()).all()
        for bucket in shared_buckets:
            if bucket.bucket_id not in owned_buckets:
                shared_bucket_id.append(bucket.bucket_id)

        shared_files = File.query.filter(File.bucket_id.in_(shared_bucket_id)).all()


        # only show files where restore time limit is None or not expired means still can backup

        # this page will show in a table what buckets the user created in a table
        # there will be links like the blog table, to update and delete buckets
        # when you click on view bucket, it should show a list of files that is in the bucket and a bucket cannot be deleted
        # until bucket is empty
        return render_template("dashboard_global_files.html", username=flask_login.current_user.get_username(),
                               filemodel=files,
                               uploadform=uploadform, sharedfilemodel=shared_files)

    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user'))

@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_files/uploadFile', methods=['POST'])
@login_required
@roles_required('EMPLOYEE')
def upload_file_to_scc(username):
    uploaded_file = request.files['file']
    file_details = UploadFileForm(request.form)
    bucket_id = file_details.bucket.data
    with app.app_context():
        target_bucket = Bucket.query.filter_by(id=bucket_id).first()
        target_bucket_key = target_bucket.sentinel_kms.get_key()
        data = cloudmersivescan(uploaded_file.stream, uploaded_file.filename)
        if uploaded_file and username == flask_login.current_user.get_username() and data is not False :

            # retrieve key from associated bucket
            encrypted_content = encrypt_with_key(key=target_bucket_key, data=data)
            new_file = File(
                id="FILE"+str(uuid.uuid4()),
                name=uploaded_file.filename,
                            encrypted_content=encrypted_content,
                            bucket_id=target_bucket.id,
                            user_id=flask_login.current_user.get_id())
            db.session.add(new_file)
            db.session.commit()
            return redirect(
                url_for('Sentinel_Routes.get_files_by_user', username=flask_login.current_user.get_username()))
        else:
            return redirect(url_for('Sentinel_Routes.authenticated_user'))

# route to delete the file
# note when deleting the file, there wont be a button in the file table to download the file
# rather the button will be replaced with a recover file button and the date before recovery expires
# note that once the date reaches, the file will be deleted from the table automatically with a cron job

# route below just adds the marker of temp delete and activates the restore
# the days_to_archive means before file cannot be recovered
# the days_to_permanent_deletion means file is still in db, but cannot recover and more for compliance




@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_files/deleteFile', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def delete_file_to_scc_temporarily(username):
    if username == flask_login.current_user.get_username():
        with app.app_context():
            # check if bucket is empty
            file_id = request.args.get('file_id')
            # retrieve the file to temp delete
            target_file = File.query.get(file_id)
            # now change the file marker for temp_delete to Deleted
            target_file.set_temp_deleted("Deleted")

            # then set time for permanent deletion
            scheduled_time = datetime.datetime.now() + datetime.timedelta(days=target_file.bucket.lifecycle_policy.days_to_archive)
            target_file.set_restore_time_limit(scheduled_time)

            db.session.commit()
        return redirect(
            url_for('Sentinel_Routes.get_files_by_user', username=flask_login.current_user.get_username()))
    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user'))

# path to download the decrypted file copy
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_files/downloadFile', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def downloadFile(username):
    if username == flask_login.current_user.get_username():
        with app.app_context():
            # check if bucket is empty
            file_id = request.args.get('file_id')
            file_to_download = File.query.get(file_id)
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
@blueprint_name.route('/sentinel_api_portal/global/dashboard/<path:username>/SSC_files/recoverFile', methods=['GET'])
@login_required
@roles_required('EMPLOYEE')
def recoverFile(username):
    if username == flask_login.current_user.get_username():
        with app.app_context():
            # check if bucket is empty
            file_id = request.args.get('file_id')
            # retrieve the file to temp delete
            target_file = File.query.get(file_id)
            # now change the file marker for temp_delete to Deleted
            target_file.set_temp_deleted("Not Deleted")

            target_file.set_restore_time_limit(None)

            db.session.commit()
        return redirect(
            url_for('Sentinel_Routes.get_files_by_user', username=flask_login.current_user.get_username()))
    else:
        return redirect(url_for('Sentinel_Routes.authenticated_user'))


