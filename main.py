#!/usr/bin/env python

from flask import Flask, render_template, request, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, auth_token_required

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'forgetme'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] = 'X-FLASK-Token'

db = SQLAlchemy(app)

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    api_key = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(50))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.before_first_request
def create_realm():
    db.create_all()
    user_datastore.create_user(api_key='bobby', name='Bobby')
    user_datastore.create_user(api_key='freddie', name='Freddie')
    db.session.commit()
    ## Monkey patching the flasksecurity callback
    current_app.extensions['security']._unauthorized_callback = lambda: abort(401)

@app.route('/')
def hello():
    return 'Peace Love & Death Metal'

@app.errorhandler(401)
def unauthorized(e):
    return "You didn't say the magic word", 401

@app.login_manager.token_loader
def authorize(token):
    return User.query.filter_by(api_key=token).first()

@app.route('/socle/<socle>/<version>/<server>', methods=['GET', 'PUT'])
@auth_token_required
def socle(socle, version, server):
    if request.method == 'GET':
        return 'You want me to install %s %s on server %s' % (socle, version, server)
    else:
        return 'Installing %s %s on %s...' % (socle, version, server)

if __name__ == '__main__':
    app.run()