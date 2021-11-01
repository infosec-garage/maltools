
"""Maltools base models"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Optional, Sequence

import pydantic
from pydantic import BaseModel, HttpUrl, conint

from ..types import SHA256, RiskScore
from ..utils import sha256sum


class IndicatorType(str, Enum):
    """Indicator types"""
    hash = 'hash'
    md5 = 'MD5'
    sha256 = 'SHA256'
    sha1 = 'SHA1'
    ipv4 = 'IPv4'
    ipv6 = 'IPv6'
    domain = 'domain'
    url = 'url'
    function = 'function'
    email = 'email'
    publisher = 'publisher'
    keyword = 'keyword'


class Indicator(BaseModel):
    """Malicious indicator base class

    This class can be overridden with a specific indicator type via subclasses.
    """
    value: Any
    type: IndicatorType
    risk_score = RiskScore(0)

    class Config:
        """Default pydantic config for MaltoolIndicators"""
        allow_population_by_field_name = True
        validate_assignment = True
        use_enum_values = True
        # Since `frozen` is still in beta, we use this and implement `__hash__` ourselves
        allow_mutation = False

    def __hash__(self):
        # Required to enable comparing 2 objects for equality
        return hash(self.value)


class MaltoolFile(BaseModel):
    """Malicious tool file base class

    A malicious file containing zero or more malicious indicators. This class
    can be overridden with a specific malicious file type via subclasseses.
    """
    name: str
    url: Optional[HttpUrl] = None
    description: Optional[str] = None
    sha256: SHA256
    # Not all files contain indicators, so optional
    indicators: Optional[Sequence[Indicator]]
    risk_score = RiskScore(0)

    @classmethod
    def parse(cls, filename: Path, url: str) -> MaltoolFile:
        # Generic MaltoolFile does not parse indicators
        sha256_hash = sha256sum(filename)

        return cls(
            name=filename.name,
            url=url,
            sha256=sha256_hash,
        )

    @pydantic.validator('risk_score', pre=True, always=True)
    def recalculate_risk_score(cls, v, *, values, **kwargs):
        """Recalculate the risk score based on Indicator scores

        If the MaltoolFile contains Indicators with risk scores higher than the
        value set on the MaltoolFile then these will elevate the risk score. If
        MaltoolFile has no risk score (i.e. 0) then the average of the Indicator
        scores will define the overal risk score of MaltoolFile.

        Examples:
        - MaltoolFile risk score of 5 and 3 indicators with risk scores of 7.
          Updated risk score: (5 + (7 + 7 + 7) / 3) /2 = 6
        - MaltoolFile with no risk score (i.e. 0) and 3 indicators with risk scores
          of 5, 8, and 9. Updated risk score: (5 + 8 + 9 ) / 3 = 7
        """
        risk_score = v

        if values['indicators']:
            indicator_scores = list([x.risk_score for x in values['indicators'] if x.risk_score > v])

            if indicator_scores:
                indicator_score_avg = sum(indicator_scores) / len(indicator_scores)

                if risk_score:
                    risk_score = (risk_score + indicator_score_avg) / 2
                else:
                    risk_score = indicator_score_avg

        return risk_score


class Maltool(BaseModel):
    """Malicious tool

    A malicious tool contains zero or more malicious tool files, each with zero
    or more malicious indicators. The final risk score of a tool is based on the
    the configured risk score in combination with any risk scores of malicious
    files or malicious indicators that are higher.

    Hosted malicious tools have no concept of malicous files and this the only
    information is the name and the URL where the tool is hosted at.
    """
    name: str
    url: Optional[HttpUrl] = None
    description: Optional[str] = None
    version: Optional[str] = None
    files: Optional[Sequence[MaltoolFile]]
    risk_score = RiskScore(0)

    @pydantic.validator('risk_score', pre=True, always=True)
    def recalculate_risk_score(cls, v, *, values, **kwargs):
        """Recalculate the risk score based on MaltoolFile scores

        If the Maltool contains MaltoolFiles with risk scores higher than the
        value set on the MaltoolFile then these will elevate the risk score. If
        Maltool has no risk score (i.e. 0) then the average of the MaltoolFile
        scores will define the overal risk score of Maltool.

        Examples:
        - Maltool risk score of 5 and 3 MaltoolFiles with risk scores of 7.
          Updated risk score: (5 + (7 + 7 + 7) / 3) /2 = 6
        - Maltool with no risk score (i.e. 0) and 3 MaltoolFiles with risk scores
          of 5, 8, and 9. Updated risk score: (5 + 8 + 9 ) / 3 = 7
        """
        risk_score = v

        if values['files']:
            files_scores = list([x.risk_score for x in values['files'] if x.risk_score > v])

            if files_scores:
                files_score_avg = sum(files_scores) / len(files_scores)

                if risk_score:
                    risk_score = (risk_score + files_score_avg) / 2
                else:
                    risk_score = files_score_avg

        return risk_score
