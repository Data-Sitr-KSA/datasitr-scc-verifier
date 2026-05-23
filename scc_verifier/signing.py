"""Ed25519 signing for attestation envelopes.

Every emitted attestation carries a real Ed25519 signature over the
canonicalized envelope (minus the proof block). A third party with the
public key can independently verify the signature; without it, the
attestation is a suggestion, not a claim.

v0.1 signing posture:
  - If a signing key is supplied via CLI or API, use it.
  - If not, generate an ephemeral key per run and emit a loud warning.
    The attestation is still cryptographically valid — it just isn't tied
    to any long-lived identity. Useful for demos, CI, and first-time use;
    not useful for anything anyone should rely on.

Key rotation / registration is out of scope for v0.1. The intended
production pattern is:
  1. Generate a keypair with `scc-verify keygen --out key.ed25519`.
  2. Publish the public key at a DID-addressable location
     (e.g., `https://<yourdomain>/.well-known/scc-verifier-keys.json`).
  3. Pass `--signing-key key.ed25519` on every verify run.

See schemas/attestation-envelope-v1.json for the envelope format.
"""

from __future__ import annotations

import base64
import hashlib
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


def generate_keypair() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 keypair. Returns the private key (public
    is derivable via .public_key())."""
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    """Persist a private key to disk as unencrypted PEM.

    Creates parent directories if they don't exist. Writes with mode 0600
    on filesystems that support it.

    For v0.1 we do not encrypt the key at rest. Production deployments
    should encrypt with a passphrase or move to an HSM/KMS. The .gitignore
    excludes *.ed25519 and *.pem so keys don't land in the repo.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        path.chmod(0o600)
    except OSError:
        # Filesystem may not support chmod (e.g., FAT) — best-effort only.
        pass


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an unencrypted PEM Ed25519 private key."""
    pem = path.read_bytes()
    loaded = load_pem_private_key(pem, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError(f"not an Ed25519 private key: {path}")
    return loaded


def save_public_key(key: Ed25519PublicKey, path: Path) -> None:
    """Persist a public key to disk as PEM."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load a PEM Ed25519 public key."""
    pem = path.read_bytes()
    loaded = load_pem_public_key(pem)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError(f"not an Ed25519 public key: {path}")
    return loaded


def ephemeral_keypair_with_warning() -> Ed25519PrivateKey:
    """Generate a single-use signing key and warn the caller.

    Attestations signed with an ephemeral key verify internally (the
    signature is mathematically valid) but cannot be verified against any
    published public key, because the public key only exists for the life
    of this process. Fine for `run-vectors` / CI / demos; not fine for
    anything a regulator, counsel, or customer relies on.
    """
    warnings.warn(
        "No signing key supplied; generating an ephemeral keypair. "
        "This attestation will be unverifiable after the process exits. "
        "Use `scc-verify keygen --out key.ed25519` and `--signing-key` "
        "for reproducible signatures.",
        UserWarning,
        stacklevel=2,
    )
    return generate_keypair()


def public_key_sha256(pubkey: Ed25519PublicKey) -> str:
    """SHA-256 of the public key's raw bytes. Used for identifying the
    key in attestations without leaking anything sensitive (the public
    key is not sensitive; the hash is just a stable identifier)."""
    raw = pubkey.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def sign_bytes(key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign raw bytes with Ed25519. Returns `ed25519:<base64url-no-pad>`.

    The `ed25519:` prefix matches schemas/attestation-envelope-v1.json's
    proofValue pattern. Base64url encoding (not standard base64) so the
    result is URL-safe and matches W3C VC conventions.
    """
    signature = key.sign(payload)
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"ed25519:{encoded}"


def verify_signature(pubkey: Ed25519PublicKey, payload: bytes, signed: str) -> bool:
    """Verify an `ed25519:<base64url>` signature against payload + pubkey.

    Returns True if valid, False otherwise. Does not raise on invalid
    signatures — invalid is a normal, expected outcome for a verifier.
    """
    if not signed.startswith("ed25519:"):
        return False
    encoded = signed[len("ed25519:") :]
    # Restore base64url padding.
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + padding)
        pubkey.verify(raw, payload)
        return True
    except Exception:
        return False
