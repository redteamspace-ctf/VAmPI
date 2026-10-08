import unittest

from flask import Flask, jsonify, request

from rate_limit import install_rate_limiting


class _Clock:
    def __init__(self):
        self.seconds = 0

    def __call__(self):
        return self.seconds


def _test_app(clock, *, legacy_failure_200=False, **limits):
    app = Flask(__name__)

    @app.get('/items/<item>')
    def item(item):
        return jsonify(item=item)

    @app.get('/health')
    def health():
        return jsonify(status='ok')

    @app.get('/users/v1/<username>')
    def lookup(username):
        return jsonify(username=username)

    @app.post('/users/v1/login')
    def login():
        if request.get_json().get('password') == 'correct':
            return jsonify(status='success', auth_token='token')
        return jsonify(status='fail', message='Invalid credentials'), 200 if legacy_failure_200 else 401

    windows = install_rate_limiting(app, clock=clock, **limits)
    return app.test_client(), windows


class RateLimitTests(unittest.TestCase):
    def test_username_lookup_has_a_larger_but_finite_allowance(self):
        client, _ = _test_app(_Clock(), route_limit=2, lookup_route_limit=5)
        for number in range(5):
            self.assertEqual(client.get('/users/v1/user' + str(number)).status_code, 200)
        self.assertEqual(client.get('/users/v1/another').status_code, 429)
        self.assertEqual(client.get('/health').status_code, 200)

    def test_route_limit_groups_object_ids_and_ignores_forwarded_headers(self):
        client, _ = _test_app(_Clock(), route_limit=3)
        for number in range(3):
            response = client.get('/items/' + str(number),
                                  headers={'X-Forwarded-For': '192.0.2.' + str(number)})
            self.assertEqual(response.status_code, 200)

        blocked = client.get('/items/another', headers={'X-Forwarded-For': '203.0.113.9'})
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers['Retry-After'], '60')
        self.assertEqual(client.get('/health').status_code, 200)

    def test_login_failures_are_limited_without_counting_successes(self):
        client, _ = _test_app(_Clock(), route_limit=100,
                              account_failure_limit=2, ip_failure_limit=5)
        for _ in range(5):
            self.assertEqual(client.post('/users/v1/login', json={
                'username': 'alice', 'password': 'correct'
            }).status_code, 200)
        for _ in range(2):
            self.assertEqual(client.post('/users/v1/login', json={
                'username': 'alice', 'password': 'wrong'
            }).status_code, 401)

        blocked = client.post('/users/v1/login', json={'username': 'ALICE', 'password': 'wrong'})
        self.assertEqual(blocked.status_code, 429)
        # One account's failures do not block another user's ordinary login.
        self.assertEqual(client.post('/users/v1/login', json={
            'username': 'bob', 'password': 'correct'
        }).status_code, 200)

    def test_ip_limit_catches_password_spraying_and_legacy_failures(self):
        client, _ = _test_app(_Clock(), legacy_failure_200=True, route_limit=100,
                              account_failure_limit=10, ip_failure_limit=3)
        for username in ('alice', 'bob', 'charlie'):
            response = client.post('/users/v1/login', json={
                'username': username, 'password': 'wrong'
            })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['status'], 'fail')
        blocked = client.post('/users/v1/login', json={
            'username': 'another', 'password': 'wrong'
        })
        self.assertEqual(blocked.status_code, 429)

    def test_blocked_requests_do_not_extend_the_window(self):
        clock = _Clock()
        client, _ = _test_app(clock, route_limit=1)
        self.assertEqual(client.get('/health').status_code, 200)
        clock.seconds = 10
        self.assertEqual(client.get('/health').status_code, 429)
        clock.seconds = 61
        self.assertEqual(client.get('/health').status_code, 200)

        client, _ = _test_app(clock, route_limit=100,
                              account_failure_limit=1, ip_failure_limit=10)
        self.assertEqual(client.post('/users/v1/login', json={
            'username': 'alice', 'password': 'wrong'
        }).status_code, 401)
        clock.seconds = 71
        self.assertEqual(client.post('/users/v1/login', json={
            'username': 'alice', 'password': 'wrong'
        }).status_code, 429)
        clock.seconds = 122
        self.assertEqual(client.post('/users/v1/login', json={
            'username': 'alice', 'password': 'wrong'
        }).status_code, 401)

    def test_storage_remains_bounded_with_many_clients(self):
        client, windows = _test_app(_Clock(), max_buckets=4)
        for number in range(100):
            response = client.get('/health', environ_overrides={
                'REMOTE_ADDR': '198.51.100.' + str(number)
            })
            self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(windows._buckets), 4)


if __name__ == '__main__':
    unittest.main()
