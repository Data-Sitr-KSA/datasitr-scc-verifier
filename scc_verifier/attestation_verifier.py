"""Third-party verification helpers for SCC attestation envelopes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scc_verifier.canonicalization import canonicalize
from scc_verifier.key_registry import KeyRegistry, RegistryError, find_key_for_envelope
from scc_verifier.schema_validator import validate_attestation_envelope
from scc_verifier.signing import public_key_sha256, verify_signature

SIGNED_ENVELOPE_FIELDS = (
    "@context",
    "type",
    "id",
    "issuer",
    "validFrom",
    "credentialSubject",
)


@dataclass(frozen=True)
class AttestationVerificationResult:
    """Result of verifying an attestation envelope with a public key."""

    schema_valid: bool
    signature_valid: bool
    verification_method_matches_key: bool
    verification_method_match_required: bool = True
    errors: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return (
            self.schema_valid
            and self.signature_valid
            and (
                self.verification_method_matches_key or not self.verification_method_match_required
            )
            and not self.errors
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "schema_valid": self.schema_valid,
            "signature_valid": self.signature_valid,
            "verification_method_matches_key": self.verification_method_matches_key,
            "verification_method_match_required": self.verification_method_match_required,
            "errors": list(self.errors),
        }


def signature_payload(envelope: dict[str, Any]) -> bytes:
    """Return the canonical payload covered by proof.proofValue.

    The verifier signs the VC envelope without the proof block. Reconstruct the
    same object by selecting the signed fields explicitly rather than mutating
    caller-owned dictionaries.
    """
    payload = {field: envelope[field] for field in SIGNED_ENVELOPE_FIELDS}
    return canonicalize(payload)


def verify_attestation_envelope(
    envelope: dict[str, Any],
    public_key: Ed25519PublicKey | KeyRegistry,
    *,
    require_verification_method_match: bool = True,
) -> AttestationVerificationResult:
    """Verify schema validity, Ed25519 signature, and key binding."""
    errors: list[str] = []

    schema_result = validate_attestation_envelope(envelope)
    if not schema_result.valid:
        errors.extend(f"schema: {e}" for e in schema_result.errors)
        return AttestationVerificationResult(
            schema_valid=False,
            signature_valid=False,
            verification_method_matches_key=False,
            verification_method_match_required=require_verification_method_match,
            errors=tuple(errors),
        )

    proof = envelope["proof"]
    if isinstance(public_key, KeyRegistry):
        try:
            registry_key = find_key_for_envelope(public_key, envelope)
        except RegistryError as e:
            errors.append(f"{type(e).__name__}: {e}")
            return AttestationVerificationResult(
                schema_valid=True,
                signature_valid=False,
                verification_method_matches_key=False,
                verification_method_match_required=True,
                errors=tuple(errors),
            )

        signature_valid = verify_signature(
            registry_key.public_key,
            signature_payload(envelope),
            proof["proofValue"],
        )
        if not signature_valid:
            errors.append("proofValue signature is invalid for the registry-resolved public key")
        return AttestationVerificationResult(
            schema_valid=True,
            signature_valid=signature_valid,
            verification_method_matches_key=True,
            verification_method_match_required=True,
            errors=tuple(errors),
        )

    expected_fragment = f"#key-{public_key_sha256(public_key)}"
    method = proof["verificationMethod"]
    method_matches = method.endswith(expected_fragment)
    if require_verification_method_match and not method_matches:
        errors.append(
            "verificationMethod does not match supplied public key "
            f"(expected suffix {expected_fragment!r})"
        )

    signature_valid = verify_signature(
        public_key,
        signature_payload(envelope),
        proof["proofValue"],
    )
    if not signature_valid:
        errors.append("proofValue signature is invalid for the supplied public key")

    return AttestationVerificationResult(
        schema_valid=True,
        signature_valid=signature_valid,
        verification_method_matches_key=method_matches,
        verification_method_match_required=require_verification_method_match,
        errors=tuple(errors),
    )
