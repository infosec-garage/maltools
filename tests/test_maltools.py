#!/usr/bin/env python

"""Maltool class unit tests"""
import pytest

from maltools.models import KeywordIndicator, Maltool, MaltoolFile


def test_maltool_incorrect_url():
    """Test creation failure of a Maltool object with an invalid URL"""
    name = 'Test incorrect URL'
    url = 'not_a_url'

    with pytest.raises(Exception) as e_info:
        Maltool(name=name, url=url)


def test_maltool_incorrect_riskscore():
    """Test creation failure of a Maltool object with an invalid risk score"""
    name = 'Test a too high risk score'
    risk_score = 15

    with pytest.raises(Exception) as e_info:
        Maltool(name=name, risk_score=risk_score)

    name = 'Test a too low risk score'
    risk_score = -10

    with pytest.raises(Exception) as e_info:
        Maltool(name=name, risk_score=risk_score)


def test_maltool_creation():
    """Test the creation of a full Maltool object"""
    name = 'Test tool'
    url = 'http://example.com'
    sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    indicator = KeywordIndicator(name='Test indicator', value='Test keyword')
    toolfile = MaltoolFile(name='Test file', sha256=sha256, indicators=[indicator])
    Maltool(name=name, url=url, files=[toolfile])
