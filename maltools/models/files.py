"""MaltoolFile model subclasses"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from ..utils import read_file, sha256sum
from .base import Indicator, MaltoolFile
from .indicators import FunctionIndicator


class PowerShellFile(MaltoolFile):
    """Malicious PowerShell file"""
    @classmethod
    def parse(cls, filename: Path, url: str) -> PowerShellFile:
        # PowerShell specific parsing function
        sha256_hash = sha256sum(filename)
        contents = read_file(filename)
        indicators: List[Indicator] = list()

        # Extract PowerShell functions
        ps_regex = r'\s*function\s*([a-zA-Z_-]*)\s*{.*'
        matches = re.findall(ps_regex, contents)
        indicators.extend(list(set([FunctionIndicator(value=match) for match in matches])))

        if indicators:
            return cls(
                name=filename.name,
                url=url,
                sha256=sha256_hash,
                indicators=indicators,
            )
        else:
            return cls(
                name=filename.name,
                url=url,
                sha256=sha256_hash,
            )
