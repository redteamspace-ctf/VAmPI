import re
import time
from collections import OrderedDict, deque
from threading import Lock
import jsonschema

from config import db
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User


LOGIN_FAILURE_LIMIT = 10
LOGIN_WINDOW_SECONDS = 60
_failed_logins = OrderedDict()
_failed_logins_lock = Lock()


def _recent_login_failures(client):
    now = time.monotonic()
    with _failed_logins_lock:
        attempts = _failed_logins.get(client)
        if attempts is None:
            return 0
        _failed_logins.move_to_end(client)
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if not attempts:
            del _failed_logins[client]
            return 0
        return len(attempts)


def _record_login_failure(client):
    now = time.monotonic()
    with _failed_logins_lock:
        attempts = _failed_logins.setdefault(client, deque())
        _failed_logins.move_to_end(client)
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        attempts.append(now)
        # Keep the in-memory table bounded if many clients send invalid logins.
        if len(_failed_logins) > 1024:
            _failed_logins.popitem(last=False)


def error_message_helper(msg):
    if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value

def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email,
                'admin': user.admin
            }
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")
        

def get_by_username(username):
    if User.get_user(username):
        return Response(str(User.get_user(username)), 200, mimetype="application/json")
    else:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")


def register_user():
    request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            # Account registration must never take privileges from client input.
            user = User(username=request_data['username'], password=request_data['password'],
                        email=request_data['email'])
            db.session.add(user)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Successfully registered. Login to receive an auth token.'
            }

            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype="application/json")


def login_user():
    request_data = request.get_json()
    client = request.remote_addr or 'unknown'

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        # Throttle failed guesses without letting attackers lock out a user who
        # knows the correct password.
        if _recent_login_failures(client) >= LOGIN_FAILURE_LIMIT:
            return Response(error_message_helper("Too many login attempts. Try again later."), 429,
                            mimetype="application/json")
        _record_login_failure(client)
        return Response(error_message_helper("Username or Password Incorrect!"), 200,
                        mimetype="application/json")
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")


def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return {'error': 'Invalid token. Please log in again.'}


def update_email(username):
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, update_email_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        email = request_data.get('email')
        # Bound the input and avoid nested quantifiers that can backtrack exponentially.
        if len(email) > 254 or not re.fullmatch(
                r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', email):
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")
        user.email = email
        db.session.commit()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email
            }
        }
        return Response(json.dumps(responseObject), 204, mimetype="application/json")


def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if username != resp['sub']:
            return Response(error_message_helper("Not authorized to change this password."), 403,
                            mimetype="application/json")
        if request_data.get('password'):
            user = User.query.filter_by(username=username).first()
            if not user:
                return Response(error_message_helper("User Not Found"), 404, mimetype="application/json")
            user.password = request_data.get('password')
            db.session.commit()
            responseObject = {
                'status': 'success',
                'Password': 'Updated.'
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")


def delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if user.admin:
            if bool(User.delete_user(username)):
                responseObject = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype="application/json")
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype="application/json")
