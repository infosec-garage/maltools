"""Indicator model subclasses"""
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import HttpUrl, NameEmail

from ..types import MD5, SHA1, SHA256, Domain
from .base import Indicator, IndicatorType


class MD5Indicator(Indicator):
    """MD5 hash indicator"""
    value: MD5
    type = IndicatorType.md5


class SHA255Indicator(Indicator):
    """SHA256 hash indicator"""
    value: SHA256
    type = IndicatorType.sha256


class SHA1Indicator(Indicator):
    """SHA1 hash indicator"""
    value: SHA1
    type = IndicatorType.sha1


class IPv4Indicator(Indicator):
    """IPv4 address indicator"""
    value: IPv4Address
    type = IndicatorType.ipv4


class IPv6Indicator(Indicator):
    """IPv6 address indicator"""
    value: IPv6Address
    type = IndicatorType.ipv6


class DomainIndicator(Indicator):
    """Domain name indicator"""
    value: Domain
    type = IndicatorType.domain


class URLIndicator(Indicator):
    """URL indicator"""
    value: HttpUrl
    type = IndicatorType.url


class FunctionIndicator(Indicator):
    """Function name indicator"""
    value: str
    type = IndicatorType.function


class EmailIndicator(Indicator):
    """Email address indicator"""
    value: NameEmail
    type = IndicatorType.email


class PublisherIndicator(Indicator):
    """Publisher name indicator"""
    value: str
    type = IndicatorType.publisher


class KeywordIndicator(Indicator):
    """Generic keyword indicator"""
    value: str
    type = IndicatorType.keyword
