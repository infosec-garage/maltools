"""Custom validated or constrained data types"""
import re

from pydantic.types import ConstrainedStr, ConstrainedInt


class RiskScore(ConstrainedInt):
    """Risk score value constrained between 0 and 10"""
    ge = 0
    le = 10


class Domain(ConstrainedStr):
    """A validated domain name string"""
    rege = re.compile(r'^(?=.{1,255}$)(?!-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})*\.?(?<!-)$')


class MD5(ConstrainedStr):
    """A validated MD5 hash string"""
    regex = re.compile(r'^[a-fA-F\d]{32}$')


class SHA1(ConstrainedStr):
    """A validated SHA1 hash string"""
    regex = re.compile(r'^[a-fA-F\d]{40}$')


class SHA256(ConstrainedStr):
    """A validated SHA256 hash string"""
    regex = re.compile(r'^[a-fA-F\d]{64}$')
