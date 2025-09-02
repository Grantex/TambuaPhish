from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField, TextAreaField, SelectField, IntegerField
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo, ValidationError, Regexp, NumberRange, URL, Optional
)
from wtforms import HiddenField
from models import User






#sign up form

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12, message='Password must be at least 12 characters long.'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).*$',
            message='Password must include uppercase, lowercase, numbers, and special characters.'
        )
    ])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Sign Up')

    def validate_password(self, password):
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'user', 'iloveyou']
        if password.data.lower() in common_passwords:
            raise ValidationError('Your password is too common. Please choose a stronger one.')
        if self.username.data.lower() in password.data.lower():
            raise ValidationError('Your password cannot contain your username.')
        if self.email.data.lower().split('@')[0] in password.data.lower():
            raise ValidationError('Your password cannot contain part of your email.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('That email is already registered.')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('That username is already taken.')

#log in form 
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

#forgot password form
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

#reset password form after clicking link sent in email
class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=12, message='Password must be at least 12 characters long.'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).*$',
            message='Password must include uppercase, lowercase, numbers, and special characters.'
        )
    ])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Reset Password')


    #------Edit Phishing Template Form--------


class EditTemplateForm(FlaskForm):
    template_name = StringField('Template Name', validators=[DataRequired()])
    sender_name = StringField('Sender Name', validators=[DataRequired()])
    subject = StringField('Subject', validators=[DataRequired()])
    email_body = HiddenField('Email Body', validators=[DataRequired()])
    submit = SubmitField('Update Template')

# Trainign module development form

class TrainingModuleForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    category = SelectField(
        "Category",
        choices=[
            ("Phishing Basics", "Phishing Basics"),
            ("Email Security", "Email Security"),
            ("Social Engineering", "Social Engineering"),
            ("Other", "Other"),
        ],
        validators=[DataRequired()]
    )
    format = SelectField(
        "Format",
        choices=[
            ("Video", "Video"),
            ("PDF", "PDF"),
            ("Interactive", "Interactive"),
            ("Link", "Link"),
        ],
        validators=[DataRequired()]
    )
    duration = IntegerField("Duration (min)", validators=[DataRequired(), NumberRange(min=1)])
    
    # TextAreaField can hold long/multiple links
    content = TextAreaField("Content (Link/Upload)", validators=[DataRequired()])
    
    submit = SubmitField("Save Module")



#Assigning a training module form

class AssignForm(FlaskForm):
    module_id = SelectField("Select Training Module", coerce=int, validators=[DataRequired()])
    emails = TextAreaField("Recipient Emails (comma-separated)", validators=[DataRequired()])
    message = TextAreaField("Custom Message (optional)", validators=[Optional()])
    submit = SubmitField("Send Assignment")