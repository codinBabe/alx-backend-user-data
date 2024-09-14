#!/usr/bin/env python3
import bcrypt
""" Encrypting passwords """


def hash_password(password: str) -> bytes:
    """ Encrypting passwords """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validate that the provided password
    matches the hashed password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
