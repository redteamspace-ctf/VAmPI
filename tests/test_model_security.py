import datetime
import unittest

import jwt

from config import db, vuln_app
from models.user_model import User


class ModelSecurityTests(unittest.TestCase):
    def setUp(self):
        self.context = vuln_app.app.app_context()
        self.context.push()
        db.drop_all()
        db.create_all()
        db.session.add(User("alice", "password", "alice@example.com"))
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_username_lookup_treats_sql_metacharacters_as_data(self):
        self.assertEqual(User.get_user("alice").username, "alice")
        self.assertIsNone(User.get_user("' OR 1=1 --"))
        self.assertIsNone(User.get_user("alice' OR '1'='1"))

    def test_old_public_jwt_key_cannot_sign_valid_tokens(self):
        forged = jwt.encode(
            {"sub": "alice", "exp": datetime.datetime.now(datetime.timezone.utc)
             + datetime.timedelta(minutes=5)},
            "random",
            algorithm="HS256",
        )
        self.assertIn("error", User.decode_auth_token(forged))
        self.assertEqual(User.decode_auth_token(User.get_user("alice").encode_auth_token("alice"))["sub"],
                         "alice")


if __name__ == "__main__":
    unittest.main()
