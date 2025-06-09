

from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField, FloatField, \
    DecimalRangeField, FileField, BooleanField
from wtforms.fields import EmailField, DateField, PasswordField, SubmitField
from flask_wtf import FlaskForm, RecaptchaField




class CreateLoginForm(FlaskForm):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired()])
    rememberme = SelectField('Remember Me', choices=['Not Enabled', 'Enabled'])

class CreateUserForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm',
                                                             message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )])
    password_confirm = PasswordField('Confirm Password',
                                     [validators.Length(min=1, max=200), validators.DataRequired(), ])

class UpdateUserForm(FlaskForm):
    username = StringField('username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    old_password = PasswordField('Old Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm', message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )
                                          ])
    password_confirm = PasswordField('Confirm Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    enable_2fa = SelectField('Enable 2FA via email OTP', choices=['Not Enabled', 'Enabled'])

class AdminUpdateUserForm(FlaskForm):
    username = StringField('username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm',
                                                             message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )
                                          ])
    password_confirm = PasswordField('Confirm Password',
                                     [validators.Length(min=1, max=200), validators.DataRequired(), ])

class EmailVerificationForm(FlaskForm):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])

class ForgetPasswordForm(FlaskForm):
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired()])
    confirm_password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired()])
    OTP = StringField('OTP Token', [validators.Length(min=1, max=200), validators.DataRequired()])

class Login2FAForm(FlaskForm):
    OTP = StringField('OTP Token', [validators.Length(min=1, max=200), validators.DataRequired()])

# class CreateRoleForm(FlaskForm):
#     rolename = StringField('Role Name', [validators.Length(min=1, max=200), validators.DataRequired()])
#     havesuperadmin_permission = SelectField('Super Admin Permission',
#                                            choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
#                                            default="Unauthorized")
#     haveemployee_permission = SelectField('Employee Permission',
#                                              choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
#                                              default="Unauthorized")
#     haveuser_permission = SelectField('User Permission',
#                                      choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
#                                      default="Unauthorized")
#
# class UpdateRoleForm(FlaskForm):
#     rolename = StringField('Role Name', [validators.Length(min=1, max=200), validators.DataRequired()])
#     havesuperadmin_permission = SelectField('Super Admin Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
#     haveemployee_permission = SelectField('Employee Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
#     haveuser_permission = SelectField('User Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")

class AddToEvirec(FlaskForm):
    path_name = StringField('Name of Evidence Path', [validators.Length(min=1, max=200), validators.DataRequired()])
    description = StringField('Description', [validators.Length(min=1, max=200)])

class UpdateEvirec(FlaskForm):
    path_name = StringField('New name of Evidence Path', [validators.Length(min=1, max=200), validators.DataRequired()])
    description = StringField('New Description', [validators.Length(min=1, max=200)])

class UploadFileForm(FlaskForm):
    file = FileField('Upload File')
    bucket = SelectField('Select Bucket')

class CreateBucketForm(FlaskForm):
    name = StringField('Name of Bucket', [validators.Length(min=1, max=200), validators.DataRequired()])
    days_to_archive = IntegerField('Days to Archive', [validators.Length(min=1, max=200), validators.DataRequired()])
    days_to_permanent_deletion = IntegerField('Days to Permanent Deletion', [validators.Length(min=1, max=200), validators.DataRequired()])
    availability = SelectField('Availability', choices=[('Private', 'Private'), ('Public', 'Public')],
                               default="Private")

class UpdateBucketForm(FlaskForm):
    name = StringField('Name of Bucket', [validators.Length(min=1, max=200), validators.DataRequired()])
    days_to_archive = IntegerField('Days to Archive', [validators.Length(min=1, max=200), validators.DataRequired()])
    days_to_permanent_deletion = IntegerField('Days to Permanent Deletion', [validators.Length(min=1, max=200), validators.DataRequired()])
    availability = SelectField('Availability', choices=[('Private', 'Private'), ('Public', 'Public')], default="Private")

class UpdateACLForm(FlaskForm):
    email = EmailField('Email to give access', [validators.Email(), validators.DataRequired()])

class AddFirewallRuleForm(FlaskForm):
    ip = StringField('IP Address', [
        validators.Length(min=1, max=200),
        validators.DataRequired(),
        validators.Regexp(
            # Regular expression pattern for IPv4 addresses (adapt as needed)
            regex=r'^(\d{1,3}\.){3}\d{1,3}$',
            message='Please enter a valid IP address'
        )
    ])

class UpdateFirewallRuleForm(FlaskForm):
    ip = StringField('IP Address', [
        validators.Length(min=1, max=200),
        validators.DataRequired(),
        validators.Regexp(
            # Regular expression pattern for IPv4 addresses (adapt as needed)
            regex=r'^(\d{1,3}\.){3}\d{1,3}$',
            message='Please enter a valid IP address'
        )
    ])

class LogFileForm(FlaskForm):
    log_file = SelectField('Select Log File', choices=[], coerce=str)
    download_button = SubmitField('Download Log File')