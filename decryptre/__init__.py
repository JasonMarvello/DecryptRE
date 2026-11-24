"""DecryptRE: offline text decryption and encryption toolkit.

Everything in this package runs locally. There are no network calls, no
telemetry and no remote wordlists.
"""

__version__ = "1.0.0"

from .models import Candidate  # noqa: F401

__all__ = ["Candidate", "__version__"]
