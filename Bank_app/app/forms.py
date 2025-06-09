from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField, FloatField, \
    DecimalRangeField, FileField, BooleanField, SelectMultipleField
from wtforms.fields import EmailField, DateField, PasswordField, SubmitField
from flask_wtf import FlaskForm, RecaptchaField
from wtforms.validators import InputRequired, NumberRange, ValidationError


class CreateBankUserForm(FlaskForm):
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
    role = SelectField('Role', choices=['USER'])

class UpdateBankUserForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    old_password = PasswordField('Old Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm',
                                                             message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )])
    password_confirm = PasswordField('Confirm Password',
                                     [validators.Length(min=1, max=200), validators.DataRequired(), ])
    enable_2fa = SelectField('Enable 2FA via email OTP', choices=['Not Enabled', 'Enabled'])


class CreateBankAdminForm(FlaskForm):
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
    role = SelectField('Role', validators=[validators.InputRequired()], choices=[])

class UpdateBankAdminForm(FlaskForm):
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
    role = SelectField('Role', choices=['EMPLOYEE', 'IT', 'MANAGER', 'EXECUTIVE'])

class UpdateBankExecForm(FlaskForm):
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



class deposit_withdraw_form(FlaskForm):
    option = SelectField('Choose type of transaction', choices=['DEPOSIT', 'WITHDRAW'])
    amount = IntegerField('Amount', validators=[
        InputRequired(),
        NumberRange(min=0, message='Amount must be greater than or equal to 0')
    ])

class transfer_form(FlaskForm):
    dst_account = StringField('Destination Account Username', [validators.Length(min=1, max=200), validators.DataRequired()])
    amount = IntegerField('Amount', validators=[
        InputRequired(),
        NumberRange(min=0, message='Amount must be greater than or equal to 0')
    ])
    password_confirm = PasswordField('Confirm transaction',
                                     [validators.Length(min=1, max=200), validators.DataRequired(), ])

class MaxTagsSelected(object):
    def __init__(self, message="You can select a maximum of 3 tags."):
        self.message = message

    def __call__(self, form, field):
        if len(field.data) > 3:
            raise ValidationError(self.message)

class UploadFileFormAPI(FlaskForm):
    file = FileField('Upload File')

    existing_tags = SelectMultipleField('Select Tags (Maximum of 3) (Hold Alt and click to select multiple tags)', coerce=str,
                                        choices=[
                                                ('Announcements', 'Announcements'), ('General', 'General'), ('Events', 'Events'),
                                                 ('Internal', 'Internal'),
                                            ('Report', 'Report'), ('Finance', 'Finance'),
                                            ('Sensitive', 'Sensitive')],
                                        validators=[MaxTagsSelected()]
                                        )

class VerifyFileForm(FlaskForm):
    file = FileField('Upload File')