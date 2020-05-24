from app import app,db #Imports app variable from app and db
from flask import render_template, flash,redirect, url_for, request, session, send_from_directory, abort
from app.forms import LoginForm,RegistrationForm,FileUpload,DDOS,ImageStegnoHide,PCAPFab, ImageStegnoShow #We import all of our forms from the forms.py
from flask_login import current_user, login_user, logout_user, login_required 
# Similar too forms but instead we import tables for our SQLite database from models.py
from app.models import User,PCAPDb
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
#This ensures nothing shady happens with filenames that could casue a security risk 
from app import PCAPCreator,ImageStegno
#This imports the two python program tools 
from subprocess import Popen, PIPE
import os

#Credit goes too this series https://www.youtube.com/watch?v=BUmUV8YOzgM&list=PLF2JzgCW6-YY_TZCmBrbOpgx5pSNBD0_L for teaching me a lot about flask as well this blog https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world 



@app.route('/') #Home /root directory
@app.route('/index')
@app.route('/root')
@app.route('/home')
def index():
    return render_template('Index.html',title='Home Page')
    #This will probably stay blank due to a lack of creativity


#This app.route means that when we do 127.0.0.0/login it will perform the code under this
@app.route('/login', methods=['GET','POST']) # We need to include post due to it not being avaliable by default
def login():
    form = LoginForm()
    if form.validate_on_submit(): #Esentially if the form is not valid then just render the login template
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data) #logs the user this allows them to access the rest of the web app
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In Page', form=form)
    #This allows me to render html templates vias flask (All templates are under the templates folder) this also passes data required for wtf forms and jinja2 templates

#Simple route to logout users
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
        #This adds the user to the SQLite databsae and redirects them too login
        flash('You are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/user/<username>') #Allows the user to see his own profile nothing special yet again im not creative
@login_required #This stops user who arent logged in being able to view these pages
def user(username):
    user = User.query.filter_by(username=username).first_or_404() #If they cant find the user within the database 404
    return render_template('profile.html', user=user)
    #Simply displays the user username very boring :(

@app.route('/PCAPAnalyser', methods=['GET','POST'])
@login_required
def PCAPAnalyser():
    form = FileUpload() # We simply import these forms like this throughout for ease
    if request.method == 'POST' and form.validate_on_submit():
        file_input = request.files['file_input']
        SafeFileName = secure_filename(file_input.filename)
        if len(SafeFileName) > 50:
            flash("You have entered a file too large")
            return redirect(url_for("PCAPAnalyser"))
        file_input.save(os.path.join(app.config["PCAP_UPLOAD_DEST"],SafeFileName))
        #This uploads the file to the directory defined by the config file
        flash('Your PCAP file has been uploaded!')
        os.system("./app/PCAPRead " + "./app/static/PCAP/" + SafeFileName)
        SafeFileName = os.path.splitext(SafeFileName)
        try:
            print(SafeFileName[0]+"Output.txt")
            return send_from_directory(app.config['PCAP_OUTPUT_DEST'], filename=SafeFileName[0]+"Output.txt", as_attachment=True)
        except FileNotFoundError:
            abort(404)
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
        PCAPCreator.Run(PCAP.id)
        #This runs the run function within PCAPCreator.py
        #This will send the user a download as an attacthement or simply 404 due to the file not being found
        try:
            return send_from_directory(app.config['PCAP_DOWNLOAD_DEST'], filename=PCAP.Output_file, as_attachment=True)
        except FileNotFoundError:
            abort(404)   
    else:
        return render_template('PCAPFAb.html', form=form, title='PCAP Creator')

#https://stackoverflow.com/questions/19794695/flask-python-buttons/19794878 Thanks for showing Flask buttons


@app.route('/StegnoEncodeDecode')
@login_required
def EncodeDecode():
    return render_template('ChooseEncodeDecode.html', title='Encode|Decode Choice')
    #Simple template with buttons allowing an user to decide what they want to the do


@app.route('/ImageDecode', methods=['GET','POST'])
@login_required
def ImageDecode():
    form = ImageStegnoShow()
    if request.method == 'POST' and form.validate_on_submit():
        file_input = request.files['file_input']
        SafeFilename = secure_filename(file_input.filename)
        file_input.save(os.path.join(app.config["UPLOAD_IMAGES_DECODE_STEGNO"],SafeFilename))
        ImageStegno.Decode(SafeFilename)
        #Runs ImageStegno Decode function
        try:
            SafeFilename = os.path.splitext(SafeFilename)
            return send_from_directory(app.config["DECODED_MESSAGES_DEST"], filename= 'Decoded' + SafeFilename[0] + ".txt", as_attachment=True)
        except FileNotFoundError:
            print("Im 404")
            abort(404)
    else:
        return render_template('UploadDecode.html', form=form, title='Decode Image')

@app.route('/ImageEncode', methods=['GET','POST'])
@login_required
def ImageEncode():
    form = ImageStegnoHide()
    if request.method == 'POST' and form.validate_on_submit():
        file_input = request.files['file_input']
        MessageSafeFilename = secure_filename(file_input.filename)
        file_input.save(os.path.join(app.config["UPLOAD_MESSAGES_ENCODE_STEGNO"],MessageSafeFilename))
        Image_file_input = request.files['Image_file_input']
        ImageSafeFilename = secure_filename(Image_file_input.filename)
        Image_file_input.save(os.path.join(app.config["UPLOAD_IMAGES_ENCODE_STEGNO"],ImageSafeFilename))
        ImageStegno.Encode(MessageSafeFilename,ImageSafeFilename)
        try:
            return send_from_directory(app.config["ENCODED_DOWNLOAD_DEST"],filename= 'Encoded' + ImageSafeFilename, as_attachment=True)
        except FileNotFoundError:
            abort(404)
    else:
        return render_template('FileUploadSQL.html', form=form, title='SQLBuster')

#https://stackoverflow.com/questions/4408377/how-can-i-get-terminal-output-in-python Credit for showing how to read the terminal

@app.route('/DDos', methods=['GET','POST'])
@login_required
def DDos():
    form = DDOS()
    if request.method == 'POST' and form.validate_on_submit():
        os.system("./DDOS " + form.ip_addr.data + " " + form.ip_addr2.data)
        print("./DDOS " + form.ip_addr.data + " " + form.ip_addr2.data)
        print(form.ip_addr.data)
        print(form.ip_addr2.data)
        flash('Sent')
        return redirect(url_for('index'))
    else:
        return render_template('DDosInput.html', form=form, title='DDOS')


