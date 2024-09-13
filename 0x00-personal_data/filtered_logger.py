#!/usr/bin/env python3
"""Regex-ing"""
import re
from typing import List


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """returns the log message obfuscated"""
    return re.sub(r"(?<={}=).*?(?={})".format(fields[0], separator),
                  redaction, message)