from app import app,db #Imports app variable from app and db
from flask import render_template, flash,redirect, url_for, request
from app.forms import LoginForm,RegistrationForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User
from werkzeug.urls import url_parse

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
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
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
'''
@login_required
@app.route('/PCAPFabricator', methods=['GET','POST'])
def PCAPFabricator():
    pass
    
@login_required
@app.route('/SQLBuster', methods=['GET','POST'])
def SQLBuster():
    pass

@login_required
@app.route('/DDos', methods=['GET','POST'])
def DDos():
    pass
'''