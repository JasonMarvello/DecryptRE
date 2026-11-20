"""The self-describing ciphertext container used for modern crypto.

AES needs a salt, an IV/nonce and the KDF settings to decrypt. Instead of
making the user remember them, DecryptRE stores them next to the ciphertext
in a small JSON envelope::

    decryptre:v1:<urlsafe-base64 of the JSON envelope>

The envelope is authenticated by AES-GCM itself; for AES-CBC a wrong
passphrase usually shows up as invalid padding.
"""

import base64
import json
from typing import Any, Dict

MAGIC = "decryptre:v1:"


class ContainerError(ValueError):
    """Raised when a container is malformed or is not a DecryptRE container."""


def is_container(text: str) -> bool:
    return text.strip().startswith(MAGIC)


def pack(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return MAGIC + token


def unpack(text: str) -> Dict[str, Any]:
    stripped = text.strip()
    if not stripped.startswith(MAGIC):
        raise ContainerError("not a DecryptRE container")
    token = stripped[len(MAGIC):]
    token += "=" * ((-len(token)) % 4)
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContainerError(f"corrupt container: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContainerError("container payload must be an object")
    return payload
