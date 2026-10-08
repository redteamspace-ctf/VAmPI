"""Exercise the patched routes together through Connexion and a real database."""

import datetime
import unittest

import jwt

from config import db, vuln_app


class ApiSecurityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app = vuln_app.app
        self.app.config['TESTING'] = True
        self.context = self.app.app_context()
        self.context.push()
        db.drop_all()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def register(self, username, **extra):
        return self.client.post('/users/v1/register', json={
            'username': username, 'password': 'pass1', 'email': f'{username}@example.com', **extra
        })

    def login(self, username, password='pass1'):
        return self.client.post('/users/v1/login', json={'username': username, 'password': password})

    def token(self, username):
        return self.login(username).get_json()['auth_token']

    @staticmethod
    def authorization(token):
        return {'Authorization': f'Bearer {token}'}

    def test_registration_login_and_user_lookup(self):
        self.assertEqual(self.register('alice').status_code, 200)
        self.assertEqual(self.register('mallory', admin=True).status_code, 400)

        wrong_password = self.login('alice', 'wrong')
        unknown_user = self.login('unknown', 'wrong')
        self.assertEqual((wrong_password.status_code, wrong_password.get_json()),
                         (unknown_user.status_code, unknown_user.get_json()))

        me = self.client.get('/me', headers=self.authorization(self.token('alice')))
        self.assertEqual(me.status_code, 200)
        self.assertFalse(me.get_json()['data']['admin'])

        self.assertEqual(self.client.get('/users/v1/_debug').status_code, 404)
        self.assertEqual(self.client.get('/users/v1/alice').get_json()['username'], 'alice')
        self.assertEqual(self.client.get('/users/v1/%27%20OR%201%3D1--').status_code, 404)

        forged = jwt.encode({
            'sub': 'alice',
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        }, 'random', algorithm='HS256')
        self.assertEqual(self.client.get('/me', headers=self.authorization(forged)).status_code, 401)

    def test_book_and_profile_mutations_are_scoped_to_owner(self):
        self.register('alice')
        self.register('bob')
        alice = self.authorization(self.token('alice'))
        bob = self.authorization(self.token('bob'))

        added = self.client.post('/books/v1', json={'book_title': 'bob-book', 'secret': 'private'}, headers=bob)
        self.assertEqual(added.status_code, 200)
        self.assertEqual(self.client.get('/books/v1/bob-book', headers=alice).status_code, 404)
        self.assertEqual(self.client.get('/books/v1/bob-book', headers=bob).get_json()['secret'], 'private')

        denied = self.client.put('/users/v1/bob/password', json={'password': 'stolen'}, headers=alice)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.login('bob').status_code, 200)

        pathological_email = 'a' * 100000 + '@example.com'
        invalid = self.client.put('/users/v1/alice/email', json={'email': pathological_email}, headers=alice)
        self.assertEqual(invalid.status_code, 400)
        valid = self.client.put('/users/v1/alice/email', json={'email': 'alice.new+tag@example.com'}, headers=alice)
        self.assertEqual(valid.status_code, 204)


if __name__ == '__main__':
    unittest.main()
