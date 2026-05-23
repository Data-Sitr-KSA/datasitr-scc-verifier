# Contributing to datasitr-scc-verifier

We welcome contributions, especially:

1. **Adversarial test vectors** — canonical SCC JSON documents that should fail verification in specific ways. The more adversarial pressure on the rule bundle, the clearer its technical boundary.
2. **Rule refinements** — corrections to existing Rego rules, with a corresponding test vector that fails before the fix and passes after.
3. **Regulatory-evolution tracking** — when SDAIA publishes new guidance, propose the corresponding rule-bundle updates.
4. **Translation / localisation** — Arabic-language rule descriptions and documentation.

We do NOT accept contributions that:

- Add AI-model dependencies. The verifier is deterministic policy-as-code by design.
- Add novel cryptography. Only well-reviewed standard primitives are acceptable.
- Bypass the human-review flag for judgment clauses. Those exist intentionally.
- Substantively change the attestation envelope shape without a corresponding major version bump.

## Governance

Rule-bundle changes follow this process:

1. Written proposal (GitHub issue or design doc).
2. Test vector coverage for the change (required — rules cannot land without an adversarial vector that fails before the fix and passes after).
3. Saudi-counsel review (for rule changes affecting legal interpretation).
4. 30-day public comment window (for rule additions, removals, or changes in interpretation).
5. SDAIA notification where applicable; no v0.x process implies ratification.
6. Signed release — the rule bundle hash changes; the new version carries a `sdaia-scc-vX.Y-YYYY-MM-DD` identifier.

Minor corrections that do not change the semantics of any rule (docs, typos, tooling) do not require the 30-day window but still require a PR with tests.

## Legal posture

Data Sitr Est. is not Saudi-licensed counsel. Contributions to the rule bundle that assert legal interpretations must cite their regulatory source. Contributors retain copyright in their contributions but license them under the project's licenses (Apache-2.0 for code and rules; CC0-1.0 for schemas and test vectors).

## Signing off

Every commit must include a Developer Certificate of Origin sign-off:

```
git commit -s -m "your message"
```

This is a statement that you have the right to submit the contribution under the project's licenses.

## Contact

Use issues for public technical problems and rule proposals. Email
`security@datasitr.com` for private security-sensitive reports.
