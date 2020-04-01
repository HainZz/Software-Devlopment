from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, IPAddress
from app.models import User
from flask_wtf.file import FileField, FileAllowed, FileRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
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
        if user:
            raise ValidationError('Please use a different username.')
    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Please use a different email address')

class FileUpload(FlaskForm):
    file_input = FileField('', validators=[FileRequired(message='You didnt upload a file'), FileAllowed(['pcap'], message='Must be a pcap file')])
    submit = SubmitField(label='Upload')

class PCAPFab(FlaskForm):
    pass

class DDOS(FlaskForm):
    ip_addr = StringField('IP Adress', validators=[DataRequired(), IPAddress(message='Invalid IP address', ipv4=True, ipv6=True)])
    submit = SubmitField(label='Enter')

class SQLBuster(FlaskForm):
    file_input = FileField('', validators=[FileRequired(message='You didnt upload a file'), FileAllowed(['txt'], message='Must be a txt file')])
    submit = SubmitField(label='Upload')