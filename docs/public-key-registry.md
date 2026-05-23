# Public Key Registry

`scc-verify verify-attestation` can verify an attestation envelope with either
a local Ed25519 public key PEM or a public key registry. The registry shape is
defined by `schemas/public-key-registry-v1.json`; the placeholder in
`examples/scc-verifier-keys.example.json` is deliberately non-functional.

## v0.3-draft Status

v0.3-draft supports local registry files and HTTPS registry URLs. The verifier
fetches the registry on each invocation, validates it against the published
schema, checks that the registry `issuer` matches the attestation `issuer`,
resolves `proof.verificationMethod`, and enforces key status/time-window
semantics. TLS is the v0.3 trust anchor for remote registry fetches.

## Operator Key Generation

Generate production signing keys on an air-gapped or otherwise hardened
machine, never inside CI and never as part of this repository:

```bash
scc-verify keygen --out ~/datasitr-signing-2026.ed25519 \
                  --public-out ~/datasitr-signing-2026.pub.pem
```

The private key file MUST NOT be committed. The repository `.gitignore` covers
`*.ed25519` and `*.pem`, but the operator is responsible for moving private key
material off the build machine immediately and protecting it under the
deployment's key-management procedure.

## Registry File Construction

Construct the registry from the public key PEM and metadata. This example uses
placeholders only:

```json
{
  "schema_version": "1",
  "issuer": "did:web:datasitr.com",
  "generated_at": "2026-05-23T00:00:00Z",
  "keys": [
    {
      "id": "key-sha256:REPLACE_WITH_64_HEX_PUBLIC_KEY_SHA256",
      "type": "Ed25519VerificationKey2020",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nREPLACE_WITH_BASE64_PEM_BODY\n-----END PUBLIC KEY-----\n",
      "status": "active",
      "not_before": "2026-05-23T00:00:00Z",
      "purpose": "primary 2026 signing key"
    }
  ]
}
```

`id` must match the verifier's key identifier for the public key. The CLI prints
that identifier during `scc-verify keygen`.

## Deployment

Publish the registry to:

```text
https://datasitr.com/.well-known/scc-verifier-keys.json
```

Deployment is handled by the datasitr.com static-site sync, outside this repo.
This repository does not source-control or publish DataSitr production key
material.

## Rotation

When a new key is generated, include both the new key and the old key:

- New key: `status: active`, with `not_before` set to the activation moment.
- Old key: `status: retired`, with `not_after` set to the rotation moment.

Retired keys remain trusted only for attestations whose `validFrom` timestamp is
inside the key's `[not_before, not_after)` window. This keeps historical
attestations verifiable after rotation.

## Revocation

If a key is compromised, set `status: revoked`, publish the registry
immediately, and issue a public disclosure describing the affected attestation
range. Revoked keys remain in the registry forever so verifiers can hard-fail
on them, but they are never trusted for any attestation regardless of timestamp.

## End-to-End Smoke

```bash
# 1. Sign an attestation
scc-verify verify --scc <doc.json> --signing-key key.ed25519 --out att.json

# 2. Verify it against the live registry once deployed
scc-verify verify-attestation \
  --attestation att.json \
  --key-registry https://datasitr.com/.well-known/scc-verifier-keys.json

# 3. Or verify it against a local registry file
scc-verify verify-attestation \
  --attestation att.json \
  --key-registry path/to/registry.json
```

Operators can inspect a registry before relying on it:

```bash
scc-verify keys list \
  --registry https://datasitr.com/.well-known/scc-verifier-keys.json
```

## Non-Claim

Publishing a public key registry does not imply SDAIA ratification of the rule
bundle, legal validity of any underlying transfer, or counsel approval of any
rule interpretation. The registry exists solely so third parties can
cryptographically reproduce the verifier's verdict against bytes the issuer
signed.
