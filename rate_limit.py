"""Small, bounded rate limits for the API's public request paths."""

import math
import time
from collections import OrderedDict, deque
from threading import Lock

from flask import jsonify, request


class _SlidingWindows:
    def __init__(self, window_seconds, max_buckets, max_events, clock):
        self.window_seconds = window_seconds
        self.max_buckets = max_buckets
        self.max_events = max_events
        self.clock = clock
        self._buckets = OrderedDict()
        self._lock = Lock()

    def _active(self, key, now):
        events = self._buckets.get(key)
        if events is None:
            return None
        while events and now - events[0] >= self.window_seconds:
            events.popleft()
        if not events:
            del self._buckets[key]
            return None
        return events

    def _make_room(self, now):
        if len(self._buckets) < self.max_buckets:
            return
        for key in list(self._buckets):
            self._active(key, now)
        while len(self._buckets) >= self.max_buckets:
            self._buckets.popitem(last=False)

    def _retry_after(self, events, limit, now):
        if events is None or len(events) < limit:
            return 0
        return max(1, math.ceil(self.window_seconds - (now - events[0])))

    def retry_after(self, limits):
        """Return seconds until every supplied (key, limit) is available."""
        now = self.clock()
        with self._lock:
            return max((self._retry_after(self._active(key, now), limit, now)
                        for key, limit in limits), default=0)

    def record(self, keys):
        now = self.clock()
        with self._lock:
            for key in keys:
                events = self._active(key, now)
                if events is None:
                    self._make_room(now)
                    events = deque(maxlen=self.max_events)
                    self._buckets[key] = events
                events.append(now)
                self._buckets.move_to_end(key)

    def allow_and_record(self, key, limit):
        """Atomically reserve one request or return a Retry-After value."""
        now = self.clock()
        with self._lock:
            events = self._active(key, now)
            retry_after = self._retry_after(events, limit, now)
            if retry_after:
                return retry_after
            if events is None:
                self._make_room(now)
                events = deque(maxlen=self.max_events)
                self._buckets[key] = events
            events.append(now)
            self._buckets.move_to_end(key)
            return 0


def install_rate_limiting(flask_app, *, route_limit=60, lookup_route_limit=600,
                          account_failure_limit=6,
                          ip_failure_limit=25, window_seconds=60, max_buckets=4096,
                          clock=time.monotonic):
    """Limit all routes per client and repeated failed login attempts.

    The connection IP is used directly; client-supplied forwarding headers are
    deliberately ignored. State lives only in this process and is bounded.
    """
    existing = flask_app.extensions.get('vampi_rate_limiting')
    if existing is not None:
        return existing

    windows = _SlidingWindows(window_seconds, max_buckets,
                              max(route_limit, lookup_route_limit,
                                  account_failure_limit, ip_failure_limit), clock)

    def client_ip():
        return request.remote_addr or 'unknown'

    def login_account():
        body = request.get_json(silent=True)
        username = body.get('username') if isinstance(body, dict) else None
        return username[:128].casefold() if isinstance(username, str) else ''

    def is_login():
        return request.method == 'POST' and request.path.rstrip('/') == '/users/v1/login'

    def too_many_requests(wait):
        response = jsonify(status='fail', message='Too many requests. Please try again later.')
        response.status_code = 429
        response.headers['Retry-After'] = str(wait)
        response.headers['Cache-Control'] = 'no-store'
        return response

    @flask_app.before_request
    def check_rate_limit():
        ip = client_ip()
        if is_login():
            failure_limits = (
                (('login-ip', ip), ip_failure_limit),
                (('login-account', ip, login_account()), account_failure_limit),
            )
            wait = windows.retry_after(failure_limits)
            if wait:
                return too_many_requests(wait)

        # Flask has already matched url_rule before running before_request.
        # The rule groups different object IDs under one route bucket.
        route = request.url_rule.rule if request.url_rule is not None else '<unmatched>'
        route_key = ('route', ip, request.method, route)
        # Username lookups are queried in batches by API clients. Keep their
        # route bounded without exhausting the smaller write-route allowance.
        limit = lookup_route_limit if request.method == 'GET' and route == '/users/v1/<username>' else route_limit
        wait = windows.allow_and_record(route_key, limit)
        if wait:
            return too_many_requests(wait)

    @flask_app.after_request
    def count_failed_login(response):
        if not is_login() or response.status_code == 429:
            return response
        payload = response.get_json(silent=True)
        failed = response.status_code >= 400 or (isinstance(payload, dict) and payload.get('status') == 'fail')
        if failed:
            ip = client_ip()
            windows.record((('login-ip', ip), ('login-account', ip, login_account())))
        return response

    flask_app.extensions['vampi_rate_limiting'] = windows
    return windows
