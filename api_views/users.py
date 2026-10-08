import re
import threading
import time
from collections import defaultdict, deque

import jsonschema
import jwt

from config import db, vuln_app
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User

# Linear-time email check (no nested quantifiers) plus a length cap, so validation cost stays bounded.
EMAIL_MAX_LENGTH = 254
EMAIL_REGEX = re.compile(r"[^@\s]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

# Failed-login throttling: per (client, username) and per client, within a sliding window.
LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_FAILURES_PER_USER = 5
LOGIN_MAX_FAILURES_PER_CLIENT = 20
_login_failures = defaultdict(deque)
_login_lock = threading.Lock()


def error_message_helper(msg):
    if isinstance(msg, dict):
        return json.dumps({"status": "fail", "message": msg['error']})
    else:
        return json.dumps({"status": "fail", "message": msg})


def _recent_failures(key, now):
    attempts = _login_failures[key]
    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts)


def _login_blocked(client, username):
    now = time.monotonic()
    with _login_lock:
        return (_recent_failures(('user', client, username), now) >= LOGIN_MAX_FAILURES_PER_USER or
                _recent_failures(('client', client), now) >= LOGIN_MAX_FAILURES_PER_CLIENT)


def _record_login_failure(client, username):
    now = time.monotonic()
    with _login_lock:
        _login_failures[('user', client, username)].append(now)
        _login_failures[('client', client)].append(now)


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Only Admins may view debug information!"), 403,
                        mimetype="application/json")
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value

def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if not user:
            return Response(error_message_helper("Invalid token. Please log in again."), 401,
                            mimetype="application/json")
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
            # only the allowed fields are used; privileged fields such as 'admin' are never taken from the client
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

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        client = request.remote_addr
        username = request_data.get('username')
        if _login_blocked(client, username):
            response = Response(error_message_helper("Too many failed login attempts. Try again later."), 429,
                                mimetype="application/json")
            response.headers['Retry-After'] = str(LOGIN_WINDOW_SECONDS)
            return response
        # fetching user data if the user exists
        user = User.query.filter_by(username=username).first()
        if User.verify_login(user, request_data.get('password')):
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        # same message for an unknown username and a wrong password, so neither can be enumerated
        _record_login_failure(client, username)
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
        if not user:
            return Response(error_message_helper("Invalid token. Please log in again."), 401,
                            mimetype="application/json")
        email = request_data.get('email')
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
        if request_data.get('password'):
            # users may only change their own password: the target comes from the token, never from the path
            if username != resp['sub']:
                return Response(error_message_helper("You can only change your own password!"), 403,
                                mimetype="application/json")
            user = User.query.filter_by(username=resp['sub']).first()
            if not user:
                return Response(error_message_helper("User Not Found"), 400, mimetype="application/json")
            user.set_password(request_data.get('password'))
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
        if user and user.admin:
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
