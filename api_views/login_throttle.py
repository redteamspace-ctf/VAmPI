import math
import threading
import time
from collections import deque

'''
 Rate limiting for the login endpoint.
 - Failed logins are counted per client address and username, and per client address across all usernames
   (password spraying). Once a limit is reached every login attempt it covers is refused, the right password
   included, until the oldest counted failure is older than the window. Successful logins clear the
   per-username count.
 - Login attempts of any outcome are also limited per client address and username, so valid credentials
   can't be used to flood the endpoint either.
'''
MAX_FAILURES_PER_USER = 5
MAX_FAILURES_PER_CLIENT = 30
FAILURE_WINDOW_SECONDS = 300
MAX_ATTEMPTS_PER_USER = 15
ATTEMPT_WINDOW_SECONDS = 10
# drop expired entries once this many keys are tracked, so random usernames can't grow memory forever
PRUNE_THRESHOLD = 10000

_WINDOWS = {'user-failures': FAILURE_WINDOW_SECONDS, 'client-failures': FAILURE_WINDOW_SECONDS,
            'user-attempts': ATTEMPT_WINDOW_SECONDS}

_lock = threading.Lock()
_events = {}


def _failure_limits(client, username):
    return ((('user-failures', client, username), MAX_FAILURES_PER_USER),
            (('client-failures', client), MAX_FAILURES_PER_CLIENT))


def _attempt_limit(client, username):
    return ('user-attempts', client, username), MAX_ATTEMPTS_PER_USER


def _recent(key, now):
    events = _events.get(key)
    if events is None:
        return None
    window = _WINDOWS[key[0]]
    while events and now - events[0] >= window:
        events.popleft()
    if not events:
        del _events[key]
        return None
    return events


def _record(key, now):
    if len(_events) > PRUNE_THRESHOLD:
        for old_key in list(_events):
            _recent(old_key, now)
    _events.setdefault(key, deque()).append(now)


def acquire(client, username):
    """Counts a login attempt. Returns 0 when it may go ahead, else the seconds until one is allowed again."""
    now = time.monotonic()
    wait = 0
    with _lock:
        for key, limit in _failure_limits(client, username) + (_attempt_limit(client, username),):
            events = _recent(key, now)
            if events and len(events) >= limit:
                # the event that has to expire before the count drops below the limit
                expires = events[len(events) - limit] + _WINDOWS[key[0]]
                wait = max(wait, math.ceil(expires - now))
        if not wait:
            _record(_attempt_limit(client, username)[0], now)
    return wait


def record_failure(client, username):
    now = time.monotonic()
    with _lock:
        for key, _ in _failure_limits(client, username):
            _record(key, now)


def record_success(client, username):
    with _lock:
        _events.pop(('user-failures', client, username), None)
