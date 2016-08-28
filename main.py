#!/usr/bin/env python

from functools import wraps
import types
import json

from flask import Flask, request, Blueprint, _request_ctx_stack
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, current_user
from flask_principal import identity_changed, Identity
from flask_restful import Api, Resource

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'forgetme'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

_unauthenticated_response = json.dumps({'message': 'You must authenticate to perform this request'}), 401,  {'Content-Type': 'application/json', 'WWW-Authenticate': 'Token realm="flask"'}
_unauthorized_repsonse = json.dumps({'message': 'You are not authorized to perform this request'}), 401,  {'Content-Type': 'application/json', 'WWW-Authenticate': 'Token realm="flask"'}
_forbidden_response = json.dumps({'message': 'You are not authorized to perform this request'}), 403, {'Content-Type': 'application/json'}

#
# UserDataStore Setup
#
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
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.before_first_request
def create_realm():
    db.create_all()

    b = user_datastore.create_user(api_key='bobby', name='Bobby')
    f = user_datastore.create_user(api_key='freddie', name='Freddie')
    t = user_datastore.create_user(api_key='tommy', name='Tommy')

    a = user_datastore.create_role(name='admin')
    u = user_datastore.create_role(name='user')

    user_datastore.add_role_to_user(b, a)
    user_datastore.add_role_to_user(b, u)
    user_datastore.add_role_to_user(f, u)

    db.session.commit()

#
#  Security Setup
#
user_bp = Blueprint('user_bp', __name__)
admin_bp = Blueprint('admin_bp', __name__)

@app.before_request
def authenticate():
    token = request.headers.get('Authorization')
    if token:
        user = User.query.filter_by(api_key=token).first()
        if user:
            # Hijack Flask-Login to set current_user
            _request_ctx_stack.top.user = user
            identity_changed.send(app, identity=Identity(user.id))
        else: 
            return _unauthorized_repsonse
    else:
        return _unauthenticated_response

def authorize(role):
    if not current_user.is_authenticated:
        return _unauthenticated_response
    if not current_user.has_role(role):
        return _forbidden_response
    return None

@user_bp.before_request
def authorize_user():
    return authorize('user')

@admin_bp.before_request
def authorize_admin():
    return authorize('admin')


#
# API Resources 
#
class Index(Resource):
    def get(self):
        return {'message': "Hello World!"}

class Users(Resource):
    def get(self):
        return {'message': "Welcome Users"}
    def put(self):
        return {'message': "New user created"}

class UserMe(Resource):
    def get(self):
        return {'message': "Welcome %s" % current_user.name}

class Admin(Resource):
    def get(self):
        return {'message': "Welcome Administrator"}

#
# API Endpoints
#
user_api = Api(user_bp)
admin_api = Api(admin_bp)

user_api.add_resource(Index, '/')
user_api.add_resource(Users, '/users')
user_api.add_resource(UserMe, '/users/me')
admin_api.add_resource(Admin, '/admin')

#
# Run Flask
#
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)
if __name__ == '__main__':
    app.run()