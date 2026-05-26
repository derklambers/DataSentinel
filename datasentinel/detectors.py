
"""
Detector registry.
"""

import re

from .models import Detector
from .validators import validate_bsn, validate_iban

DETECTORS = [

    # Email detection
    Detector(
        name="Email Address",
        severity="LOW",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
    ),

    # OpenAI API key detection
    Detector(
        name="OpenAI API Key",
        severity="HIGH",
        pattern=re.compile(
            r"sk-[A-Za-z0-9]{20,}"
        ),
        mask_value=True,
    ),

    # Dutch IBAN detection
    Detector(
        name="Dutch IBAN",
        severity="MEDIUM",
        pattern=re.compile(
            r"\bNL\d{2}[A-Z]{4}\d{10}\b"
        ),
        validator=validate_iban,
    ),

    # Dutch BSN detection
    Detector(
        name="BSN",
        severity="HIGH",
        pattern=re.compile(
            r"\b\d{8,9}\b"
        ),
        validator=validate_bsn,
    ),
]
