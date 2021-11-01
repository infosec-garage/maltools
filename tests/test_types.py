#!/usr/bin/env python

"""Custom validated type unit tests"""
import pytest

from maltools.types import MD5, SHA1, SHA256, Domain, RiskScore


def test_domain_type():
    domain1 = 'example.com'
    domain2 = 'www.example.com'
    domain3 = 'example.co.uk'
    Domain.validate(domain1)
    Domain.validate(domain2)
    Domain.validate(domain3)


def test_md5_type():
    md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    MD5.validate(md5)


def test_sha1_type():
    sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    SHA1.validate(sha1)


def test_sha256_type():
    sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    SHA256.validate(sha256)
