#!/usr/bin/env python3
"""Auth module
"""

from user import User
from db import DB
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(password: str) -> str:
    """Hash password
        """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate a UUID
    """
    return str(uuid4())


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

    def valid_login(self, email: str, password: str) -> bool:
        """Validate login
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    user.hashed_password)
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Create a session
        """
        User = None
        try:
            User = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if User is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(User.id, session_id=session_id)
        return session_id
    
    def get_user_from_session_id(self, session_id: str) -> str:
        """Get user from session id
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            if user is not None:
                return user
        except NoResultFound:
            return None
        return None
    
    def destroy_session(self, user_id: int) -> None:
        """Destroy session
        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)
        return None