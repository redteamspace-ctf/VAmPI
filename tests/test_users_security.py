"""Regression checks for the public user endpoints' security boundaries."""

from types import SimpleNamespace
from unittest.mock import patch

from config import vuln_app
from api_views import users


class FakeQuery:
    def __init__(self, accounts):
        self.accounts = accounts
        self.username = None

    def filter_by(self, username):
        self.username = username
        return self

    def first(self):
        return self.accounts.get(self.username)


class FakeUser:
    accounts = {}
    query = FakeQuery(accounts)

    def __init__(self, username, password, email, admin=False):
        self.username = username
        self.password = password
        self.email = email
        self.admin = admin

    def encode_auth_token(self, username):
        return f'token-for-{username}'


class FakeSession:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, account):
        self.added.append(account)

    def commit(self):
        self.commits += 1


def test_debug_route_does_not_fetch_private_user_fields():
    with patch.object(users.User, 'get_all_users_debug', side_effect=AssertionError('private data fetched')), \
            patch.object(users.User, 'get_user', side_effect=AssertionError('username looked up')):
        response = vuln_app.app.test_client().get('/users/v1/_debug')
    assert response.status_code == 404
    assert b'password' not in response.data


def test_login_has_same_failure_for_unknown_user_and_bad_password():
    alice = FakeUser('alice', 'correct', 'alice@example.com')
    FakeUser.accounts = {'alice': alice}
    FakeUser.query = FakeQuery(FakeUser.accounts)
    with patch.object(users, 'User', FakeUser):
        with vuln_app.app.test_request_context('/users/v1/login', method='POST',
                                               json={'username': 'alice', 'password': 'wrong'}):
            wrong_password = users.login_user()
        with vuln_app.app.test_request_context('/users/v1/login', method='POST',
                                               json={'username': 'missing', 'password': 'wrong'}):
            unknown_user = users.login_user()
        with vuln_app.app.test_request_context('/users/v1/login', method='POST',
                                               json={'username': 'alice', 'password': 'correct'}):
            successful = users.login_user()
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.data == unknown_user.data
    assert successful.status_code == 200
    assert b'auth_token' in successful.data


def test_registration_rejects_admin_and_does_not_reveal_existing_accounts():
    session = FakeSession()
    FakeUser.accounts = {'existing': FakeUser('existing', 'secret', 'existing@example.com')}
    FakeUser.query = FakeQuery(FakeUser.accounts)
    with patch.object(users, 'User', FakeUser), patch.object(users, 'db', SimpleNamespace(session=session)):
        with vuln_app.app.test_request_context('/users/v1/register', method='POST',
                                               json={'username': 'new', 'password': 'secret',
                                                     'email': 'new@example.com', 'admin': True}):
            admin_attempt = users.register_user()
        with vuln_app.app.test_request_context('/users/v1/register', method='POST',
                                               json={'username': 'new', 'password': 'secret',
                                                     'email': 'new@example.com'}):
            new_account = users.register_user()
        with vuln_app.app.test_request_context('/users/v1/register', method='POST',
                                               json={'username': 'existing', 'password': 'secret',
                                                     'email': 'existing@example.com'}):
            existing_account = users.register_user()
    assert admin_attempt.status_code == 400
    assert len(session.added) == 1
    assert session.added[0].admin is False
    assert new_account.status_code == existing_account.status_code == 200
    assert new_account.data == existing_account.data


def test_password_change_requires_matching_token_subject():
    alice = FakeUser('alice', 'old', 'alice@example.com')
    bob = FakeUser('bob', 'old', 'bob@example.com')
    FakeUser.accounts = {'alice': alice, 'bob': bob}
    FakeUser.query = FakeQuery(FakeUser.accounts)
    session = FakeSession()
    with patch.object(users, 'User', FakeUser), patch.object(users, 'db', SimpleNamespace(session=session)), \
            patch.object(users, 'token_validator', return_value={'sub': 'alice'}):
        with vuln_app.app.test_request_context('/users/v1/bob/password', method='PUT',
                                               json={'password': 'stolen'}):
            denied = users.update_password('bob')
        with vuln_app.app.test_request_context('/users/v1/alice/password', method='PUT',
                                               json={'password': 'updated'}):
            allowed = users.update_password('alice')
    assert denied.status_code == 403
    assert bob.password == 'old'
    assert allowed.status_code == 204
    assert alice.password == 'updated'
    assert session.commits == 1


def test_email_validation_rejects_pathological_input_and_accepts_normal_address():
    alice = FakeUser('alice', 'secret', 'old@example.com')
    FakeUser.accounts = {'alice': alice}
    FakeUser.query = FakeQuery(FakeUser.accounts)
    session = FakeSession()
    with patch.object(users, 'User', FakeUser), patch.object(users, 'db', SimpleNamespace(session=session)), \
            patch.object(users, 'token_validator', return_value={'sub': 'alice'}):
        with vuln_app.app.test_request_context('/users/v1/alice/email', method='PUT',
                                               json={'email': 'a' * 100000 + '@example.com'}):
            rejected = users.update_email('alice')
        with vuln_app.app.test_request_context('/users/v1/alice/email', method='PUT',
                                               json={'email': 'alice.new+tag@example.com'}):
            accepted = users.update_email('alice')
    assert rejected.status_code == 400
    assert accepted.status_code == 204
    assert alice.email == 'alice.new+tag@example.com'
    assert session.commits == 1
