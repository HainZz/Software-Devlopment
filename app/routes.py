from app import app,db #Imports app variable from app and db
from flask import render_template, flash,redirect, url_for, request, session, send_file
from app.forms import LoginForm,RegistrationForm,FileUpload,DDOS,ImageStegnoHide,PCAPFab
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User,DosDb,PCAPDb
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
import os
import Murat


@app.route('/') #Home /root directory
@app.route('/index')
@app.route('/root')
@app.route('/home')
def index():
    return render_template('Index.html',title='Home Page')


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In Page', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)

@app.route('/PCAPAnalyser', methods=['GET','POST'])
@login_required
def PCAPAnalyser():
    form = FileUpload()
    if request.method == 'POST' and form.validate_on_submit():
        file_input = request.files['file_input']
        SafeFileName = secure_filename(file_input.filename)
        file_input.save(os.path.join(app.config["PCAP_UPLOAD_DEST"],SafeFileName))
        flash('Your PCAP file has been uploaded!')
        return redirect(url_for('index'))
    else:
        return render_template('FileUpload.html', form=form, title='PCAP Upload')

@app.route('/PCAPFabricator', methods=['GET','POST'])
@login_required
def PCAPFabricator():
    form = PCAPFab()
    if request.method == 'POST' and form.validate_on_submit():
        PCAP = PCAPDb(message=form.Message.data,port=form.Port.data,src_ip=form.Source_IP.data,Dest_ip=form.Dest_IP.data,Dest_mac=form.Destination_Mac_Adress.data,Source_mac=form.Source_Mac_Adress.data,Output_file=form.Output_File_Name.data)
        db.session.add(PCAP)
        db.session.commit()
        flash('Your PCAP information has been saved')
        return redirect(url_for('index'))
    else:
        return render_template('PCAPFAb.html', form=form, title='PCAP Creator')

#https://stackoverflow.com/questions/19794695/flask-python-buttons/19794878 Thanks for showing Flask buttons



@app.route('/StegnoEncodeDecode')
@login_required
def EncodeDecode():
    return render_template('ChooseEncodeDecode.html', title='Encode|Decode Choice')

@app.route('/ImageSoundDecode')
@login_required
def ImageSoundDecode():
    return render_template('ChooseSoundImageDecode.html', title='Sound|Image Choice')

@app.route('/ImageSoundEncode')
@login_required
def ImageSoundEncode():
    return render_template('ChooseSoundImageEncode.html', title='Sound|Image Choice')

@app.route('/ImageDecode', methods=['GET','POST'])
@login_required
def ImageDecode():
    pass

@app.route('/SoundDecode', methods=['GET','POST'])
@login_required
def SoundDecode():
    pass

@app.route('/SoundEncode', methods=['GET','POST'])
@login_required
def SoundEncode():
    pass

@app.route('/ImageEncode', methods=['GET','POST'])
@login_required
def ImageEncode():
    form = ImageStegnoHide()
    if request.method == 'POST' and form.validate_on_submit():
        file_input = request.files['file_input']
        SafeFilename = secure_filename(file_input.filename)
        file_input.save(os.path.join(app.config["UPLOAD_MESSAGES_ENCODE_STEGNO"],SafeFilename))
        Image_file_input = request.files['Image_file_input']
        SafeFilename = secure_filename(Image_file_input.filename)
        Image_file_input.save(os.path.join(app.config["UPLOAD_IMAGES_ENCODE_STEGNO"],SafeFilename))
        flash('Your files have been uploaded!')
        return redirect(url_for('index'))
    else:
        return render_template('FileUploadSQL.html', form=form, title='SQLBuster')


@app.route('/DDos', methods=['GET','POST'])
@login_required
def DDos():
    form = DDOS()
    if request.method == 'POST' and form.validate_on_submit():
        NewRequest = DosDb(ip_addr=form.ip_addr.data)
        db.session.add(NewRequest)
        db.session.commit()
        flash('Your IP has been uploaded')
        return redirect(url_for('index'))
    else:
        return render_template('DDosInput.html', form=form, title='DDOS')


