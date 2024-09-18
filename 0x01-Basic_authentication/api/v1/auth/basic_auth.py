#!/usr/bin/env python3
""" Module of API Authentification"""
import re
import base64
import binascii
from flask import request
from typing import List, TypeVar
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ BasicAuth class"""
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header
        for a Basic Authentication.
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Decodes a base64-encoded authorization header.
        """
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
            ) -> (str, str):
        """Extracts the user credentials from a decoded Base64 string.
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>.+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern, decoded_base64_authorization_header)
            if field_match is not None:
                return (
                    field_match.group('user'), field_match.group('password'))
        return (None, None)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on his email and password.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                user = User.search({'email': user_email})
            except Exception:
                return None
            if len(user) == 0:
                return None
            if not user[0].is_valid_password(user_pwd):
                return user[0]
        return None
