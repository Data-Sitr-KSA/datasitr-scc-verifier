# SCC Template Conformance Path

This repository currently validates DataSitr's canonical SCC JSON form. It does
not yet prove that a signed legal document exactly matches SDAIA's official SCC
text.

The path to official-template conformance is:

1. **Template selection.** The canonical form declares one of the four SDAIA
   role templates: controller-to-controller, controller-to-processor,
   processor-to-processor, or processor-to-controller. `scc-canonical-v1.json`
   validates that the declared role pair matches the exporter/importer roles.
2. **Official text inventory.** A future bundle should store canonical clause
   identifiers and hashes derived from the official SDAIA template text.
3. **Permitted blanks.** The extractor must distinguish fields intended to be
   completed by parties from mandatory SCC text that cannot be modified.
4. **Document extraction.** A future parser should map a signed SCC document
   into the canonical JSON representation and preserve clause-level evidence.
5. **Conflict checks.** Additional commercial terms must be checked for direct
   or indirect conflict with mandatory SCC clauses.
6. **Counsel-reviewed rule freeze.** Any rule that encodes legal interpretation
   needs source citation, interpretation boundary, Saudi counsel review, public
   comment, and signed release artifacts before it can be described as more
   than draft.

Until those steps exist, this project remains a draft canonical-form verifier,
not an official SDAIA SCC text verifier.
