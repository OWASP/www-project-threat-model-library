# CycloneDX profile decision log

Decisions taken while building the CycloneDX 2.0 profile for the OWASP Threat Model Library.
Newest status first, then decisions in the order they were made.

## Status (2026-10-13)

- **For discussion:** the pull request that adds this profile is opened to discuss the schema, not
  to merge it as final. Nothing here is agreed yet.
- **Done:** one example, [Husky AI](husky-ai-threat-model-cyclonedx-2.0.json), converted from
  [`threat-models/ai-ml-systems/husky-ai-threat-model.json`](../threat-models/ai-ml-systems/husky-ai-threat-model.json).
  It validates against the profile and converts back to the original exactly.
- **On hold:** the other library models. They will be converted once the schema is agreed.
  All six already convert without loss; CI checks this on every pull request.
- **Open:** CycloneDX gaps raised with the CycloneDX working group (see the end of this file).

## Decisions

### 1. Build from the parity branch of the CycloneDX fork

The CycloneDX models come from
[`P3tra-WP/specification`](https://github.com/P3tra-WP/specification), branch
`2.0-dev-threatmodeling-library-parity`, commit `7973584` (16 September 2026). That is the newest
threat-modelling work, including the `inScope` flags. The commit is pinned in `build-schema.sh`.

### 2. Bundle with the fork's own bundler, and make the bundle self-contained

The schema is bundled with the fork's `tools/src/main/js/bundler`, so it matches how CycloneDX
builds its own schemas. The SPDX, behaviour taxonomy and cryptography definition schemas are
bundled in as well. The previous bundle left 8 `$ref`s pointing at `../specification/schema/…`, a
path that only existed on the author's machine, so it failed to compile in a strict validator.
The rebuild is reproducible: running `build-schema.sh` again gives a byte-identical file.

### 3. One schema, one folder

Everything lives in `cyclonedx/`: the source schema (the file to edit), one bundled schema, the
build script and the example. The earlier root-level bundle, both minified bundles and the old
`cyclonedx-threat-models/` folder were removed.

### 4. The profile is prescriptive

The profile is CycloneDX 2.0 plus rules that require everything `threat-model.schema.json`
requires. A document missing any library-required element is rejected. This was tested by
removing each required element from Husky AI in turn (24 cases), and all 24 were rejected.
Specifically:

- exactly one blueprint;
- enums limited to the values the mapping uses;
- `bom-ref`s in the form `<kind>:<symbolic-name>`, so references always convert back;
- required library properties enforced, with their allowed values.

JSON Schema cannot check that a reference resolves, or that each threat has exactly one scenario;
the converter checks those.

### 5. No data loss, and loud failure otherwise

Each library field goes to a native CycloneDX field when one has the same meaning. Otherwise it
goes to a property named `org.owasp.threat-model-library.<name>` on the closest owning object.
`scripts/cyclonedx_convert.py check` proves that converting to CycloneDX and back returns the
original document exactly. During development, fixtures covering every field and every enum value
of the library schema were also checked.

If a value cannot be represented without loss, the converter stops with an error rather than
dropping it. The only such case is a trust boundary from a zone to itself, because CycloneDX
boundaries need two distinct zones.

### 6. Stay valid CycloneDX; don't patch the models in the profile

Where CycloneDX has no field, we use a property rather than extend a CycloneDX model inside the
profile. Extending a model would make our documents invalid for every other CycloneDX tool. For
example, `scope.tier` would be neater, but `blueprint.scope` does not allow extra fields.

### 7. Duplicate list entries are kept exactly

CycloneDX lists must not contain duplicates. When a library list does, the CycloneDX field gets
the de-duplicated list and the exact original goes into a property. Husky AI has one such case: a
trust boundary that lists `password` twice.

### 8. CWE titles ride on a link to the CWE page

A CycloneDX `weakness` holds either a `cweId` or a `name`, never both, and CycloneDX 1.7 stored
CWEs as bare integers. Each CWE title therefore goes on the threat as a `documentation` external
reference to `https://cwe.mitre.org/data/definitions/<id>.html`, with the title in `comment`. This
also gives CycloneDX readers a working link. We decided not to change the `weakness` model in the
fork; the gap is raised with the CycloneDX working group instead.

### 9. Release and review dates use blueprint metadata

`reviewed_at` goes to `metadata.reviewDate`, and `released_at` to `metadata.validityPeriod.start`
("when the blueprint becomes valid"). CycloneDX needs a full date-time, so a plain date becomes
midnight UTC and the original date is kept in a property. `product_release_date` stays a property,
because release notes would need an invented `type`.

### 10. Controls link to threats with a `mitigates` relationship

A CycloneDX control has no field for the threats it mitigates. Each control's threats are recorded
as a blueprint relationship from the control:

```json
{ "ref": "control:<name>", "custom": [{ "type": "mitigates", "targets": ["threat:<name>"] }] }
```

This keeps the link readable from the control and in native order. Each threat also lists its
controls in `threat.mitigations`, the direction CycloneDX uses throughout its threat model.
Alternatives considered and rejected:

- **`control.appliesTo`:** defined as the elements a control protects, which a threat is not.
- **`riskResponse.addresses`:** responses only exist inside a risk, and library controls are not
  linked to risks.
- **A `bom-link` external reference:** meant for outside documents, with no fitting type.

### 11. Components are blueprint assets

Library components become blueprint `assets` of type `component`, not top-level CycloneDX
`components`. A top-level component requires a `type` (application, service, …) that the library
does not record, so we would have had to invent one. Parent components become `contains`
relationships.

### 12. Threats are split into a threat and a scenario

Following the parity commit, each library threat becomes a CycloneDX threat plus one scenario. The
scenario holds the triggering `event` and the threat persona (`threatProfile`). Threat sources map
one-to-one to `origin`, using the NIST SP 800-30 types.

### 13. Risks become inherent risk ratings

Likelihood, impact, impact description, score and level become `inherentRisk`, with methodology
`qualitative-matrix`. CycloneDX has five risk levels to the library's six, so `very_low` and
`very_high` are also kept in a property.

### 14. Values with no CycloneDX field are properties

| Library field | Why there is no CycloneDX field |
|---|---|
| Scope criticality, exposure, tier, data sensitivity | `blueprint.scope` allows no extra fields; criticality exists only per asset |
| Actor title | A persona-type party has no name |
| Persona `is_person`, `access_level`, `malicious_intent`, `applicability_to_org` | Threat profiles have no fields for these attacker attributes |
| Control priority | Priority only exists on risk responses |
| `product_release_date`, `$schema` | No equivalent |

### 15. A few values are added for CycloneDX readers

These are derived or required by CycloneDX, and they are ignored when converting back:

- an attacker `sophistication` derived from skill level;
- a scenario `accessLevel` derived from the persona;
- diagram type `architecture`;
- model types `architecture` and `data-flow`;
- zone and boundary type `trust`;
- the converter as the producing tool in `metadata.tools`.

### 16. Husky AI replaces the hand-made example

The earlier hand-made Husky AI CycloneDX file was removed. It was missing control priorities,
scenario events, actor names, risk ratings and the scope classification, and it fails the
prescriptive profile. The converted file replaces it.

### 17. Fixtures are not committed

The coverage fixtures were used during development but are not kept in the branch, to keep it
small while the schema is under discussion. CI runs the round-trip check on the six library
models.

## Raised with the CycloneDX working group

1. Controls have no `priority`.
2. A `weakness` cannot hold both a `cweId` and a name.
3. Threat profiles cannot record malicious intent, person or automated, access level or
   applicability.
4. Persona-type actors cannot have a name.
5. No criticality, exposure, tier or data sensitivity for the system as a whole; `blueprint.scope`
   is the natural place.
6. `riskScore.level` has five values; the library matrix has six bands.
7. The fork's bundler skips its own validation on 2020-12 schemas, and its default bundle keeps
   relative external `$ref`s.
8. A control cannot say which threats it mitigates; the link only exists as `threat.mitigations`.
