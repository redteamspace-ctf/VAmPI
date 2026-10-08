import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from config import vuln_app
from api_views.books import get_by_title
from models.books_model import Book
from models.user_model import User


class _Result:
    def __init__(self, row):
        self.row = row

    def first(self):
        return self.row


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter_by(self, **criteria):
        return _Result(next(
            (row for row in self.rows
             if all(getattr(row, field) == value for field, value in criteria.items())),
            None,
        ))


class BookAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.alice = SimpleNamespace(id=1, username='alice')
        self.bob = SimpleNamespace(id=2, username='bob')
        self.alice_book = SimpleNamespace(
            user_id=1, user=self.alice, book_title='alice-book', secret_content='alice-secret'
        )
        self.bob_book = SimpleNamespace(
            user_id=2, user=self.bob, book_title='bob-book', secret_content='bob-secret'
        )

    def lookup(self, username, title):
        with vuln_app.app.test_request_context(
            '/books/v1/' + title, headers={'Authorization': 'Bearer test-token'}
        ):
            with patch('api_views.books.token_validator', return_value={'sub': username}), \
                    patch.object(User, 'query', _Query([self.alice, self.bob])), \
                    patch.object(Book, 'query', _Query([self.alice_book, self.bob_book])):
                return get_by_title(title)

    def test_owner_can_read_own_secret(self):
        response = self.lookup('alice', 'alice-book')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.get_data(as_text=True)), {
            'book_title': 'alice-book', 'secret': 'alice-secret', 'owner': 'alice'
        })

    def test_other_user_cannot_read_secret(self):
        response = self.lookup('alice', 'bob-book')
        self.assertEqual(response.status_code, 404)
        self.assertNotIn('bob-secret', response.get_data(as_text=True))

    def test_missing_book_and_other_users_book_look_the_same(self):
        other_user_book = self.lookup('alice', 'bob-book')
        missing_book = self.lookup('alice', 'missing-book')
        self.assertEqual(other_user_book.status_code, missing_book.status_code)
        self.assertEqual(other_user_book.get_data(), missing_book.get_data())

    def test_deleted_token_subject_cannot_read_a_book(self):
        response = self.lookup('deleted-user', 'alice-book')
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('alice-secret', response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
