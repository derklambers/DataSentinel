
from dataclasses import dataclass
import re
from typing import Callable, Optional

@dataclass
class Finding:
    """
    Represents a detected issue.
    """
    severity: str
    type: str
    file: str
    line: int
    value: str

@dataclass
class Detector:
    """
    Reusable detector configuration.
    """
    name: str
    severity: str
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]] = None
    mask_value: bool = False
