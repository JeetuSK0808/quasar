"""Quasar — a static malware analyzer that turns a sample into an explained, ATT&CK-mapped report.

TQG Research. Parses samples, never executes them.
"""
from .analyze import analyze, VERSION

__all__ = ["analyze", "VERSION"]
__version__ = VERSION
