import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-ask'
    #This Protects against CSRF and this above will try and make the SECRET_KEY an enviroment variable but if it cant use the string
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS= False
    UPLOAD_IMAGES_ENCODE_STEGNO = '/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/Images'
    UPLOAD_MESSAGES_ENCODE_STEGNO = '/home/hainzz/Software-Devlopment/app/static/Stegno/Encode/Messages'
    UPLOAD_IMAGES_DECODE_STEGNO = '/home/hainzz/Software-Devlopment/app/static/Stegno/Decode/Images'
    PCAP_UPLOAD_DEST = '/home/hainzz/Software-Devlopment/app/static/PCAP'
