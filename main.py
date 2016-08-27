#!/usr/bin/env python

from functools import wraps
import types

from flask import Flask, render_template, request, abort, current_app, Response
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, auth_token_required, current_user
from flask_principal import Permission, RoleNeed
from flask_restful import Api, Resource

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'forgetme'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECURITY_TOKEN_AUTHENTICATION_HEADER'] = 'Authorization'

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

    b = user_datastore.create_user(api_key='bobby', name='Bobby')
    f = user_datastore.create_user(api_key='freddie', name='Freddie')
    t = user_datastore.create_user(api_key='tommy', name='Tommy')

    a = user_datastore.create_role(name='admin')
    u = user_datastore.create_role(name='user')

    user_datastore.add_role_to_user(b, a)
    user_datastore.add_role_to_user(b, u)
    user_datastore.add_role_to_user(f, u)

    db.session.commit()

@app.login_manager.token_loader
def authorize(token):
    return User.query.filter_by(api_key=token).first()

def any_role(*roles):
    """
    Flask-Security's @roles_accepted decoration returns HTTP 401 when roles expected are missing 
    Yet we wish to return HTTP 403
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perm = Permission(*[RoleNeed(role) for role in roles])
            if perm.can():
                return fn(*args, **kwargs)
            else:
                abort(403)
        return decorated_view
    return wrapper

def all_roles(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perms = [Permission(RoleNeed(role)) for role in roles]
            for perm in perms:
                if not perm.can():
                    abort(403)
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

api = Api(app)

def api_router(self, *args, **kwargs):
    def wrapper(cls):
        self.add_resource(cls, *args, **kwargs)
        return cls
    return wrapper

api.route = types.MethodType(api_router, api)

@api.route('/')
class Index(Resource):
    def get(self):
        return {'message': "Hello World!"}

@api.route('/admin')
class Admin(Resource):
    @auth_token_required
    @all_roles('admin')
    def get(self):
        return {'message': "Welcome Administrator"}

@api.route('/users')
class Users(Resource):
    @auth_token_required
    @any_role('admin', 'user')
    def get(self):
        return {'message': "Welcome User"}
    
    @auth_token_required
    @any_role('admin')
    def put(self):
        return {'message': "New user created"}

@api.route('/users/me')
class UserMe(Resource):
    @auth_token_required
    @any_role('admin', 'user')
    def get(self):
        return {'message': "Welcome %s" % current_user.name}

if __name__ == '__main__':
    app.run()