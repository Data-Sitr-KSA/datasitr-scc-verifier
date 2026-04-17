# Contributing to datasitr-scc-verifier

We welcome contributions, especially:

1. **Adversarial test vectors** — SCC documents that should fail verification in specific ways. The more adversarial pressure on the rule bundle, the stronger the guarantee.
2. **Rule refinements** — corrections to existing Rego rules, with a corresponding test vector that fails before the fix and passes after.
3. **Regulatory-evolution tracking** — when SDAIA publishes new guidance, propose the corresponding rule-bundle updates.
4. **Translation / localisation** — Arabic-language rule descriptions and documentation.

We do NOT accept contributions that:

- Add AI-model dependencies. The verifier is deterministic policy-as-code by design.
- Add novel cryptography. Only well-reviewed standard primitives are acceptable.
- Bypass the human-review flag for judgment clauses. Those exist intentionally.
- Substantively change the attestation envelope shape without a corresponding major version bump.

## Governance

Rule-bundle changes follow the process in `docs/governance.md`:

1. Written proposal (GitHub issue or design doc)
2. Test vector coverage for the change (required)
3. Saudi-counsel review (for rule changes affecting legal interpretation)
4. 30-day public comment window
5. SDAIA notification (courtesy pre-ratification; required post-ratification)
6. Signed release

## Legal posture

Data Sitr Est. is not Saudi-licensed counsel. Contributions to the rule bundle that assert legal interpretations must cite their regulatory source. Contributors retain copyright in their contributions but license them under the project's licenses (Apache-2.0 for code and rules; CC0-1.0 for schemas and test vectors).

## Signing off

Every commit must include a Developer Certificate of Origin sign-off:

```
git commit -s -m "your message"
```

This is a statement that you have the right to submit the contribution under the project's licenses.

## Contact

Issues for technical problems. Email `sulayman@datasitr.com` for anything legal-adjacent.
