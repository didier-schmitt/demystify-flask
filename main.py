#!/usr/bin/env python

from functools import wraps

from flask import Flask, render_template, request, abort, current_app, Response
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, auth_token_required, current_user
from flask_principal import Permission, RoleNeed

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
    user_datastore.add_role_to_user(f, u)

    db.session.commit()

    ## Monkey patching the flasksecurity callback
    current_app.extensions['security']._unauthorized_callback = lambda: abort(401)

@app.route('/')
def hello():
    return 'Peace Love & Death Metal'

@app.errorhandler(401)
def unauthorized(e):
    return "You didn't say the magic word", 401, {'WWW-Authenticate': 'Token realm="Flask"'}

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
                return Response("You are not authorized to perform this request", 403)
        return decorated_view
    return wrapper

@app.route('/socle/<socle>/<version>/<server>', methods=['GET', 'PUT'])
@auth_token_required
@any_role('admin', 'user') 
def socle(socle, version, server):
    if request.method == 'GET':
        return 'You want me to install %s %s on server %s' % (socle, version, server)
    else:
        if not  current_user.has_role('admin'):
            abort(403)
        return 'Installing %s %s on %s...' % (socle, version, server)

if __name__ == '__main__':
    app.run()