"""DecryptRE: offline text decryption and encryption toolkit.

Everything in this package runs locally. There are no network calls, no
telemetry and no remote wordlists.
"""

__version__ = "0.3.1"

from .models import Candidate  # noqa: F401

__all__ = ["Candidate", "__version__"]
