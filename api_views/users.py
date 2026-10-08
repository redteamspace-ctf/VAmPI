import jsonschema

from config import db
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User


def error_message_helper(msg):
    return json.dumps({'status': 'fail', 'message': msg['error'] if isinstance(msg, dict) else msg})


def _valid_email(email):
    """Validate ordinary email addresses in bounded, linear time."""
    if not isinstance(email, str) or not email.isascii() or len(email) > 254 or email.count('@') != 1:
        return False
    local, domain = email.split('@')
    if not local or len(local) > 64 or not domain or len(domain) > 253:
        return False
    if not local[0].isalnum() or not local[-1].isalnum() or '..' in local:
        return False
    if any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-' for char in local):
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum():
            return False
        if any(not (char.isalnum() or char == '-') for char in label):
            return False
    return len(labels[-1]) >= 2


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def debug():
    # The diagnostic route must never disclose passwords or privilege flags.
    return Response(error_message_helper('Not found'), 404, mimetype='application/json')

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
    # The retired debug path otherwise matches the generic username route.
    if username == '_debug':
        return Response(error_message_helper('Not found'), 404, mimetype='application/json')
    user = User.get_user(username)
    if user is None:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")
    return jsonify(user.json())


def register_user():
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, register_user_schema)
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")

    # Registration accepts only public profile fields, regardless of the
    # application's vulnerable-mode setting.
    user = User.query.filter_by(username=request_data['username']).first()
    if user is None:
        user = User(username=request_data['username'], password=request_data['password'],
                    email=request_data['email'], admin=False)
        db.session.add(user)
        db.session.commit()

    response_object = {
        'status': 'success',
        'message': 'If the username is available, the account has been registered.'
    }
    return Response(json.dumps(response_object), 200, mimetype='application/json')


def login_user():
    request_data = request.get_json(silent=True)

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
        return Response(error_message_helper('Invalid username or password.'), 401,
                        mimetype='application/json')
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    except Exception:
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
    request_data = request.get_json(silent=True)
    try:
        jsonschema.validate(request_data, update_email_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    if username != resp['sub']:
        return Response(error_message_helper('Forbidden'), 403, mimetype='application/json')
    if not _valid_email(request_data['email']):
        return Response(error_message_helper('Please provide a valid email address.'), 400,
                        mimetype='application/json')
    user = User.query.filter_by(username=username).first()
    if user is None:
        return Response(error_message_helper('User not found'), 404, mimetype='application/json')
    user.email = request_data['email']
    db.session.commit()
    return Response(status=204)


def update_password(username):
    request_data = request.get_json(silent=True)
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    if username != resp['sub']:
        return Response(error_message_helper('Forbidden'), 403, mimetype='application/json')
    if not isinstance(request_data, dict) or not isinstance(request_data.get('password'), str) or not request_data['password']:
        return Response(error_message_helper('Malformed Data'), 400, mimetype='application/json')
    user = User.query.filter_by(username=username).first()
    if user is None:
        return Response(error_message_helper('User not found'), 404, mimetype='application/json')
    user.password = request_data['password']
    db.session.commit()
    return Response(status=204)


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
