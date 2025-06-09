import os
import secrets

from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, g, abort, \
    send_from_directory
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from Sentinel_api.SentinelSuite.IAM_DB import db, init_db


# before start, run these commands:
# Navigate to the directory where your Sentinel_api application is located.
# flask --app app db init
# flask db migrate
# flask db upgrade
# flask db downgrade



app = Flask(__name__, template_folder='../templates_sentinel', static_folder='../static')
# load environ vars
print(os.getcwd())
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config', '.env_sentinel'))
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SESSION_COOKIE_NAME'] = 'sentinel_app_session'
app_secret_key = "SENTINELSUITE"
app.config['SECRET_KEY'] = app_secret_key

# Configure your app settings, database, and other configurations here
# in reality, there will be instructions on putting a domain link to the db
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/Sentineldb'
app.config['WTF_CSRF_ENABLED'] = True

# validater config file
#newrelic-admin validate-config newrelic.ini

# start app with new relic agent
#EW_RELIC_CONFIG_FILE=newrelic.ini newrelic-admin run-program $YOUR_COMMAND_OPTIONS

# use below to connect logs and infrastructure (optional)
#[Net.ServicePointManager]::SecurityProtocol = 'tls12, tls'; (New-Object System.Net.WebClient).DownloadFile("https://download.newrelic.com/install/newrelic-cli/scripts/install.ps1", "$env:TEMP\install.ps1"); & $env:TEMP\install.ps1; $env:NEW_RELIC_API_KEY='NRAK-KELY6VUXONARO2KBWOHCEINWB47'; $env:NEW_RELIC_ACCOUNT_ID='4243377'; & 'C:\Program Files\New Relic\New Relic CLI\newrelic.exe' install -n logs-integration

# Initialize common database
init_db(app)
migrate = Migrate(app, db, render_as_batch=True)
# enable csrf protection

# connect to new relic
# import newrelic.agent
#
# newrelic.agent.initialize('newrelic.ini')

csrf = CSRFProtect(app)
csrf.init_app(app)


login_manager = LoginManager(app)

with app.app_context():
    db.create_all()  # In case user table doesn't exists already. Else remove it.

from Sentinel_api.app.routes import blueprint_name, api_blueprint
# jinja function to check required roles
def check_permission(user, required_role):
    user_role = user.get_role()

    # get the role permissions
    role_permission = db.session.execute(
        db.select(SentinelRoleModel).filter_by(rolename=user_role)).scalar_one()
    if role_permission.get_superadmin_permission() == "Authorized":
        return True
    elif required_role == "DEVELOPER" and role_permission.get_developer_permission() == "Authorized":
        return True
    elif required_role == "EMPLOYEE" and role_permission.get_employee_permission() == "Authorized":
        return True
    else:
        return False

def get_all_email_of_bucket(bucket_id):
    return BucketAccess.query.filter_by(bucket_id=bucket_id).all()

def get_all_evirec_of_pathname_helper(pathname):
    # given a evirec pathname
    # return all logs with that pathname as a list
    with app.app_context():
        return EVIRECModel.query.join(LogsModel).filter(EVIRECModel.path_name == pathname).all()

def get_log_evirec_helper(log_id):
    with app.app_context():
        return LogsModel.query.filter(LogsModel.log_id == log_id).first()
#
def mask_iam_user_id(usr_id):
    unmasked_id = usr_id.split("-")[0]
    masked_length = len(usr_id) - len(unmasked_id)
    masked_id = unmasked_id + "*" * masked_length
    return masked_id

def phone_mask_first_6(phone):
    masked_phone = phone[:9] + "*" * 4
    return masked_phone

def iamAccessGiven(email):
    with app.app_context():
        if SentinelUserModel.query.filter_by(email=email).first() and SentinelIAMAccessUsers.query.filter_by(email=email).first():
            return True
        else:
            return False

def not_iam(email):
    if SentinelIAMAccessUsers.query.filter_by(email=email).first():
        return False
    else:
        return True


app.jinja_env.globals.update(check_permission=check_permission)
app.jinja_env.globals.update(get_all_email_of_bucket=get_all_email_of_bucket)
app.jinja_env.globals.update(get_all_evirec_of_pathname=get_all_evirec_of_pathname_helper)
app.jinja_env.globals.update(get_log_evirec_helper=get_log_evirec_helper)
app.jinja_env.globals.update(mask_iam_user_id=mask_iam_user_id)
app.jinja_env.globals.update(phone_mask_first_6=phone_mask_first_6)
app.jinja_env.globals.update( iamAccessGiven= iamAccessGiven)
app.jinja_env.globals.update( not_iam= not_iam)

from Sentinel_api.app import routes

app.register_blueprint(blueprint_name, url_prefix='/')
app.register_blueprint(api_blueprint)
csrf.exempt(api_blueprint)


# Import the user loader function
from Sentinel_api.app.models import load_user_sentinel, SentinelRoleModel, BucketAccess, EVIRECModel, LogsModel, \
    SentinelUserModel, SentinelIAMAccessUsers

login_manager.user_loader(load_user_sentinel)

if __name__ == "__main__":
    app.run(debug=True, port=6500, ssl_context=('cert.pem', 'key.pem'))