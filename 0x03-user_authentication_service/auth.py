#!/usr/bin/env python3
"""Auth module
"""

from user import User
from db import DB
from bcrypt import hashpw, gensalt
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> str:
    """Hash password
        """
    return hashpw(password.encode(), gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))
