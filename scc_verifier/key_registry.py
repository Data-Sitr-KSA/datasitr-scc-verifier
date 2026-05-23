"""Public key registry loading and attestation key resolution."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from scc_verifier._version import __version__
from scc_verifier.schema_validator import validate_public_key_registry

_FRAGMENT_SHA256_RE = re.compile(r"^key-sha256:[0-9a-f]{64}$")
_FRAGMENT_HEX_RE = re.compile(r"^key-[0-9a-f]{64}$")


@dataclass(frozen=True)
class RegistryKey:
    id: str
    public_key: Ed25519PublicKey
    status: str
    not_before: datetime
    not_after: datetime | None
    purpose: str | None


@dataclass(frozen=True)
class KeyRegistry:
    schema_version: str
    issuer: str
    generated_at: datetime
    keys: tuple[RegistryKey, ...]


class RegistryError(RuntimeError):
    """Base class for key-registry loading and resolution failures."""


class KeyNotFoundError(RegistryError):
    """No registry key matched the attestation verificationMethod."""


class KeyStatusError(RegistryError):
    """A matching key is present but has a hard-fail status."""


class KeyWindowError(RegistryError):
    """A matching key is outside its accepted verification window."""


def _parse_datetime(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise RegistryError(f"{field} must be a date-time string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise RegistryError(f"{field} is not a valid RFC 3339 date-time") from e
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        if field.startswith("registry"):
            raise RegistryError("registry timestamps must include timezone offset")
        raise RegistryError(f"{field} must include timezone offset")
    return parsed.astimezone(UTC)


def _public_key_from_pem(pem: str) -> Ed25519PublicKey:
    try:
        loaded = load_pem_public_key(pem.encode("utf-8"))
    except Exception as e:
        raise RegistryError("registry key public_key_pem is not a valid PEM public key") from e
    if not isinstance(loaded, Ed25519PublicKey):
        raise RegistryError("registry key public_key_pem is not an Ed25519 public key")
    return loaded


def _parse_registry(document: dict[str, Any]) -> KeyRegistry:
    result = validate_public_key_registry(document)
    if not result.valid:
        raise RegistryError("registry failed schema validation: " + "; ".join(result.errors))

    keys: list[RegistryKey] = []
    for entry in document["keys"]:
        keys.append(
            RegistryKey(
                id=entry["id"],
                public_key=_public_key_from_pem(entry["public_key_pem"]),
                status=entry["status"],
                not_before=_parse_datetime(entry["not_before"], field="registry not_before"),
                not_after=(
                    _parse_datetime(entry["not_after"], field="registry not_after")
                    if "not_after" in entry
                    else None
                ),
                purpose=entry.get("purpose"),
            )
        )

    return KeyRegistry(
        schema_version=document["schema_version"],
        issuer=document["issuer"],
        generated_at=_parse_datetime(document["generated_at"], field="registry generated_at"),
        keys=tuple(keys),
    )


def _load_registry_bytes(raw: bytes, *, source: str) -> KeyRegistry:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RegistryError(f"registry at {source} is not valid JSON") from e
    if not isinstance(document, dict):
        raise RegistryError(f"registry at {source} must be a JSON object")
    return _parse_registry(document)


def load_registry_from_path(path: Path) -> KeyRegistry:
    """Load and validate a public key registry from a local filesystem path."""
    return _load_registry_bytes(path.read_bytes(), source=str(path))


def load_registry_from_url(url: str, *, timeout: float = 10.0) -> KeyRegistry:
    """Load and validate a public key registry from an HTTPS URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        observed = f"{parsed.scheme}://" if parsed.scheme else "<missing>://"
        raise RegistryError(f"only https:// URLs are accepted; got {observed}")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"scc-verify/{__version__} (registry-client)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.URLError as e:
        raise RegistryError(f"failed to fetch registry: {e}") from e
    return _load_registry_bytes(raw, source=url)


def load_registry(location: str) -> KeyRegistry:
    """Dispatch: 'https://...' -> URL fetch; 'file://...' or bare path -> file."""
    parsed = urllib.parse.urlparse(location)
    if parsed.scheme in {"http", "https"}:
        return load_registry_from_url(location)
    if parsed.scheme == "file":
        return load_registry_from_path(Path(urllib.request.url2pathname(parsed.path)))
    if parsed.scheme:
        raise RegistryError(f"unsupported registry location scheme: {parsed.scheme}://")
    return load_registry_from_path(Path(location))


def _registry_id_from_verification_method(method: Any) -> str:
    if not isinstance(method, str):
        raise RegistryError("envelope proof.verificationMethod must be a string")
    if "#" not in method:
        raise RegistryError(f"unsupported verificationMethod: {method!r}")
    fragment = method.rsplit("#", 1)[1]
    if _FRAGMENT_SHA256_RE.fullmatch(fragment):
        return fragment
    if _FRAGMENT_HEX_RE.fullmatch(fragment):
        return f"key-sha256:{fragment.removeprefix('key-')}"
    raise RegistryError(f"unsupported verificationMethod: {method!r}")


def _verification_time(envelope: dict[str, Any], at: datetime | None) -> datetime:
    if at is not None:
        if at.tzinfo is None or at.utcoffset() is None:
            raise RegistryError("verification time must include timezone offset")
        return at.astimezone(UTC)
    try:
        return _parse_datetime(envelope["validFrom"], field="envelope validFrom")
    except KeyError as e:
        raise RegistryError("envelope is missing validFrom") from e


def find_key_for_envelope(
    registry: KeyRegistry,
    envelope: dict[str, Any],
    *,
    at: datetime | None = None,
) -> RegistryKey:
    """Resolve the envelope's verificationMethod to a registry key.

    Retired keys remain acceptable for historical attestations whose
    verification time falls inside the key's active window. Revoked keys are
    rejected regardless of timestamp.
    """
    envelope_issuer = envelope.get("issuer")
    if registry.issuer != envelope_issuer:
        raise RegistryError(
            "registry issuer does not match envelope issuer "
            f"(registry={registry.issuer!r}, envelope={envelope_issuer!r})"
        )

    try:
        method = envelope["proof"]["verificationMethod"]
    except KeyError as e:
        raise RegistryError("envelope is missing proof.verificationMethod") from e
    wanted_id = _registry_id_from_verification_method(method)

    key = next((candidate for candidate in registry.keys if candidate.id == wanted_id), None)
    if key is None:
        raise KeyNotFoundError(f"no registry key found for {wanted_id}")

    if key.status == "revoked":
        raise KeyStatusError(f"registry key {key.id} is revoked")

    verify_at = _verification_time(envelope, at)
    if verify_at < key.not_before:
        raise KeyWindowError(
            f"registry key {key.id} is not valid before {key.not_before.isoformat()}"
        )
    if key.not_after is not None and verify_at >= key.not_after:
        raise KeyWindowError(
            f"registry key {key.id} is not valid at or after {key.not_after.isoformat()}"
        )

    return key
