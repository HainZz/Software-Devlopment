from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from app.models import User
from flask_wtf.file import FileField, FileAllowed, FileRequired

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid Email Adddress.')])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid Email Address.')])
    password = PasswordField('Password', validators=[DataRequired()])
    RepeatPassword = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address')

class FileUpload(FlaskForm):
    file_input = FileField('', validators=[FileRequired(message='You didnt upload a file'), FileAllowed(['pcap'], message='Must be a pcap file')])
    submit = SubmitField(label='Upload')
