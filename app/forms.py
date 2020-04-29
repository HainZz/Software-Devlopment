from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, IPAddress, MacAddress, NumberRange
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
    Message = StringField('PCAP Message', validators=[DataRequired()])
    Port = IntegerField('Port Number', validators=[DataRequired(),NumberRange(min=0, max=65535, message="Invalid Port Number")])
    Source_IP = StringField('Source IP Adress', validators=[DataRequired(), IPAddress(message='Invalid IP address', ipv4=True)])
    Dest_IP = StringField('Destination IP Adress', validators=[DataRequired(), IPAddress(message='Invalid IP address', ipv4=True)])
    Destination_Mac_Adress = StringField('Destination Mac Adress', validators=[DataRequired(), MacAddress(message='Invalid MAC Adress')])
    Source_Mac_Adress = StringField('Source MAC Adress', validators=[DataRequired(), MacAddress(message='Invalid MAC Adress')])
    Output_File_Name = StringField('Output File Name', validators=[DataRequired()])
    Submit = SubmitField('CREATE')

class DDOS(FlaskForm):
    ip_addr = StringField('IP Adress', validators=[DataRequired(), IPAddress(message='Invalid IP address', ipv4=True)])
    submit = SubmitField(label='Enter')

class ImageStegnoHide(FlaskForm):
    Image_file_input = FileField('Image Upload', validators=[FileRequired(message='You didnt upload a image file'),FileAllowed(['png','bmp','jpeg'], message='Must be of the format PNG|BMP|JPEG')])
    file_input = FileField('Message Upload', validators=[FileRequired(message='You didnt upload a  text file'), FileAllowed(['txt'], message='Must be a txt file')])
    submit = SubmitField(label='Upload')