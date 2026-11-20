"""Small shared data structures used across DecryptRE."""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Candidate:
    """One possible decryption result.

    Attributes:
        text: The decrypted (or decoded) text.
        method: Short method name, e.g. ``"caesar"`` or ``"base64"``.
        params: Method parameters needed to reproduce the result, e.g.
            ``{"shift": 3}``. Must contain JSON-friendly values only.
        score: English-likelihood score from :mod:`decryptre.scorer`.
            Higher is better.
        depth: How many peel steps produced this candidate (0 = input).
        parent: Human-readable description of where this came from.
    """

    text: str
    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    depth: int = 0
    parent: str = ""

    def signature(self) -> str:
        """A stable key used for cycle detection and de-duplication."""
        items = ",".join(f"{k}={self.params[k]!r}" for k in sorted(self.params))
        return f"{self.method}|{items}|{self.text}"

    def describe_params(self) -> str:
        if not self.params:
            return ""
        return " ".join(f"{k}={v}" for k, v in sorted(self.params.items()))
