from app import app #Imports app variable from app
from flask import render_template


@app.route('/') #Home /root directory
@app.route('/index')
@app.route('/root')
@app.route('/home')
def index():
    return render_template('Index.html',title='Home Page')