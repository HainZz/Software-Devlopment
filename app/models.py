from app import db
from app import login
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
    def check_password(self,password):
        return check_password_hash(self.password_hash, password)

class PCAPFiles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    FileName = db.Column(db.String(64))
    data = db.Column(db.LargeBinary)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))