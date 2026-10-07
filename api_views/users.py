import re
import threading
import time
import jsonschema
import jwt

from config import db, vuln_app
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User

# Login throttling: at most LOGIN_MAX_ATTEMPTS unsuccessful attempts per client and username
# within LOGIN_WINDOW_SECONDS; a successful login clears the counter.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60
_login_attempts = {}
_login_attempts_lock = threading.Lock()

# Linear-time email check, bounded in length (no nested quantifiers to backtrack on)
EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
EMAIL_MAX_LENGTH = 254


def reserve_login_attempt(key):
    # Check and record atomically so a concurrent burst cannot slip past the limit
    now = time.time()
    with _login_attempts_lock:
        attempts = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            _login_attempts[key] = attempts
            return False
        attempts.append(now)
        _login_attempts[key] = attempts
        return True


def clear_login_attempts(key):
    with _login_attempts_lock:
        _login_attempts.pop(key, None)


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
    user = User.get_user(username)
    if user:
        return Response(json.dumps(user.json()), 200, mimetype="application/json")
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
            # The admin flag is never taken from the client
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
    attempt_key = (request.remote_addr, str((request_data or {}).get('username')))
    if not reserve_login_attempt(attempt_key):
        return Response(error_message_helper("Too many login attempts. Please try again later."), 429,
                        mimetype="application/json")

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            clear_login_attempts(attempt_key)
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        # Same answer whether the user is unknown or the password is wrong
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
        email = str(request_data.get('email'))
        if len(email) <= EMAIL_MAX_LENGTH and EMAIL_REGEX.fullmatch(email):
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
        else:
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")


def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if username != resp['sub']:
            return Response(error_message_helper("You can only change your own password!"), 401,
                            mimetype="application/json")
        if request_data.get('password'):
            user = User.query.filter_by(username=resp['sub']).first()
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
