# Public Key Registry

`scc-verify verify-attestation` verifies an attestation envelope with an
Ed25519 public key. Production deployments should publish the active public key
set at:

```text
https://<issuer-domain>/.well-known/scc-verifier-keys.json
```

The registry shape is defined by
`schemas/public-key-registry-v1.json`. The example in
`examples/scc-verifier-keys.example.json` is deliberately non-functional and
does not contain a DataSitr production key.

Current status for `v0.2.2-draft`:

- The verifier can generate private/public keypairs with `scc-verify keygen`.
- The verifier can verify an attestation with `scc-verify verify-attestation`.
- DataSitr has not published a production `.well-known` key registry as part of
  this repository.
- A future signed release should publish the active public key, key-rotation
  policy, and release-bundle hash together.
