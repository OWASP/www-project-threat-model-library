# CycloneDX profile decision log

Decisions taken while building the CycloneDX 2.0 profile for the OWASP Threat Model Library.
Newest status first, then decisions in the order they were made.

## Status (2026-10-13)

- **For discussion:** the pull request that adds this profile is opened to discuss the schema, not
  to merge it as final. Nothing here is agreed yet.
- **Done:** two examples.
  - [Husky AI](husky-ai-threat-model-cyclonedx-2.0.json), converted from
    [`threat-models/ai-ml-systems/husky-ai-threat-model.json`](../threat-models/ai-ml-systems/husky-ai-threat-model.json).
    It validates against the profile and converts back to the original exactly.
  - [LF AI & Data code assistant](lfai-code-assistant-threat-model-cyclonedx-2.0.json), built from LF AI's
    `definition.md`, assets/controls/threats tables and the "Threat modeling - Use case: Code Assistant"
    spreadsheet. It validates against the profile and is CycloneDX only. **Values LF AI has not recorded
    were assumed for the example and are pending LF AI review**; each carries an annotation starting
    "Assumed for this example, pending LF AI review".
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
- `bom-ref`s in the form `<prefix>-<symbolic-name>`, so references always convert back (see the
  bom-ref naming entry under decision 18);
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
{ "ref": "control-<name>", "custom": [{ "type": "mitigates", "targets": ["threat-<name>"] }] }
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

### 18. The profile must also hold LF AI & Data threat models without loss

The LF AI & Data Use Cases and Threat Modeling subgroup models AI systems (first use case: the
code assistant) in CycloneDX, and plans to publish them in this library. Each LF AI element was
tested against the profile; gaps are being worked through one at a time.

- **Use cases:** already supported and optional (`definitions.useCases`, referenced from
  `blueprint.useCases`). No change.
- **Flows (2026-10-13):** flows may be any CycloneDX flow type (`control`, `process`, `event`, …),
  with `sequence`, `synchronous` and `protocols`. `encrypted` is required only on `data` flows,
  which are the library's data flows. Converting a non-data flow back to the library format stops
  with an error, because the library format only has data flows.
- **Relationships (2026-10-13):** every predefined CycloneDX relationship kind (`aggregates`,
  `associates`, `composes`, `contains`, `dependsOn`, `generalizes`, `realizes`, `serves`) is
  allowed between any modelled elements, referenced by bom-ref. LF AI uses `aggregates` for
  zone membership and `composes` for an agentic framework's parts. The only custom kind is a
  control's `mitigates` link. Converting back keeps component-contains-component as
  `parent_component`; any other relationship stops with an error.
- **Assets (2026-10-13):** an asset may be of any CycloneDX asset type (`component`, `agent`,
  `model`, `tool`, `data`, …) with a name and description, or may reference a BOM component through
  `componentRef` (for example an ML model with its model card). **Every asset must name its trust
  zone**, in both forms. LF AI information assets (developer identity, session tokens, codebase
  clone) are `data` assets, placed in their component with a `contains` relationship. Library
  components have no type, so converting back stops with an error for any asset that isn't
  `type: component`; LF AI documents therefore live in CycloneDX only.
- **Where controls apply (2026-10-13):** `control.appliesTo` accepts any modelled element (assets,
  zones, flows, data stores, data sets, trust boundaries), and several of them, so LF AI controls
  can sit on the components they protect. A control without `appliesTo` applies to the whole system
  (LF AI's universal controls). Converting back only accepts a single trust boundary, which is all
  a library control can hold; anything else stops with an error. Before this change the converter
  skipped other targets without saying so; that is fixed.
- **Where threats sit (2026-10-13):** `threat.affectedAssets` accepts any modelled element (assets
  of any type, flows, data stores, data sets, zones), so LF AI threats located on a flow ("between
  the assistant plugin and the backend") or a data asset fit. Converting back accepts components
  only, as the library's `components_affected` does; anything else stops with an error.
- **MITRE ATLAS and ATT&CK (2026-10-13):** an attack pattern is CAPEC (`ap-capec-<id>`, with a
  `capecId`), MITRE ATLAS (`ap-atlas-<id>`, e.g. `ap-atlas-aml-t0051-001`) or MITRE ATT&CK
  (`ap-attack-<id>`, e.g. `ap-attack-t1195-002`). ATLAS and ATT&CK patterns have no `capecId`, keep
  the exact MITRE ID (`AML.T0051.001`) in the fork's existing `techniques` field, each entry with
  an `id` or a `tactic` (tactic only covers mappings such as the clinician scribe's `TA0029`).
  Threats can reference all three. Converting back stops with an error for ATLAS and ATT&CK, as
  library attack mechanisms are CAPEC only.
- **Diagram formats (2026-10-13):** diagrams may also be draw.io (`application/vnd.jgraph.mxfile`)
  or PNG (`image/png`, which must be base64-encoded). **The diagram source stays required**: a
  diagram kept elsewhere, such as LF AI's Mural data flow diagram, must be exported and embedded; a
  link may sit alongside it. Converting back stops with an error for draw.io and PNG, which the
  library format does not list.
- **Actor zone and title (2026-10-13):** no change; **every actor must name its trust zone and
  have a title**, as library actors do. LF AI's agent actors (a `system` party of kind `agent`,
  already accepted) lack both in their JSON, but `definition.md` gives each actor a name and a
  location, so this is missing data for LF AI to add, not data loss.
- **Threat persona attributes (2026-10-13):** `skillSet` and `applicability-to-org` are
  **optional**; `is-person`, `access-level` and `malicious-intent` stay required. LF AI's attacker
  types (External Attacker, Malicious Insider, Careless Insider, Vendor Employee, Vendor) imply the
  three required ones but record no skill level or applicability. Library models keep both, so they
  still round-trip; a document without them cannot convert back, and the converter says so.
- **Scenario event (2026-10-13):** no change; **every scenario keeps a required `event`**. 24 of
  LF AI's 51 threats (T08, T10–T29, T44–T46) have a blank Action column, but each has a threat
  statement containing the action and a NIST SP 800-30 threat event, so LF AI fills `event` from
  those. Missing data to add, not data loss.
- **bom-ref naming (2026-10-13):** bom-refs follow the style of the CycloneDX examples in the fork
  (`zone-dmz`, `df-login`, `act-customer`): lowercase, `<prefix>-<symbolic-name>`. This replaces the
  earlier `<kind>:<name>` colon style. Prefixes: `zone`, `bnd` (trust boundary), `act` (actor),
  `asset`, `store` (data store), `dataset`, `flow`, `asm` (assumption), `tp` (threat persona),
  `threat`, `ts` (scenario), `ap-capec` / `ap-atlas` / `ap-attack` (attack patterns), `control`,
  `risk`, `uc` (use case). No prefix starts another, so a reference's kind can always be read back.
  IDs are lowercase: LF AI's `T01` becomes `threat-t01`, with "T01" kept in the threat's name if
  wanted. Sub use cases need no ID segment, because each use case already lists its flows; LF AI's
  `flow:1a:agent-authenticates` becomes `flow-1a-agent-authenticates`. Because zone names contain
  hyphens, a trust boundary's zones are read from the boundary itself, not its bom-ref; a control
  naming an undeclared zone pair keeps that pair in a property.
- **Zone types (2026-10-13):** no change; zones stay `type: trust`. LF AI's Internal, External SaaS
  and External Cloud zones are trust zones.
- **NIST SP 800-30 (2026-10-13):** no new fields. LF AI's NIST threat events go in `scenario.event`
  (one string, so a threat with two NIST events writes both into it). The NIST threat source is
  covered by `threat.origin` (adversarial, accidental, structural, environmental) plus the threat
  persona's `is-person` (individual or organisation), `access-level` (outsider, insider, privileged)
  and `malicious-intent`; the exact NIST label, such as "Supplier", can go in the persona's name or
  description. The AI-generated source, event and impact justifications become `annotations` on the
  threat, with the AI tool as annotator. NIST adverse impacts are handled with scenario impact.
- **Scenario impact (2026-10-13):** no schema change; use CycloneDX's native `scenario.impact`.
  LF AI's impact text goes in `impact.description` and each NIST adverse impact in
  `impact.categories` as a custom `{"name": "HARM TO ASSETS - Loss of intellectual property"}`.
  CycloneDX requires an impact `level` (negligible, low, moderate, major, catastrophic), so **LF AI
  rates each impact**. Optional, since library models have no scenario impact.
- **Converting back refuses what it cannot hold (2026-10-13):** converting a CycloneDX document back
  to the library format used to read only the fields the library has and ignore the rest, so use
  cases, annotations, scenario impact, STRIDE categories, attack paths and similar CycloneDX-only
  data were silently dropped. Now the converter rebuilds the CycloneDX document from its result and
  stops if anything differs, naming the first field that would be lost (for example
  `$.threats.scenarios[0].impact: missing after round trip`). Only `serialNumber` is ignored,
  because it is derived from the content. Library models still convert back unchanged.
- **AI framework mappings (2026-10-13):** no schema change. OWASP Top 10 for LLM Applications, IBM
  AI Risk Atlas and Databricks DASF 2.0 mappings go on the threat as `documentation` external
  references to the framework's page, the same pattern as CWE titles, with the comment written as
  `<framework> <id>: <name>`, for example `OWASP LLM01:2025 Prompt Injection`,
  `IBM AI Risk Atlas: Data poisoning`, `DASF 2.0: Data Poisoning`. `threat.categories` cannot be
  used because CycloneDX fixes its taxonomies to STRIDE, LINDDUN, MAESTRO and MITRE-ATTACK; and
  standards cannot be linked from a threat, only from a risk.
- **AI-specific flag (2026-10-13):** an optional threat property
  `org.owasp.threat-model-library.ai-specific`, at most one, valued `yes`, `no` or `partly`. LF AI
  uses it to decide whether a threat also gets a CSA AICM control mapping. Their mixed answers
  ("Y – some of it is agent autonomy, N – some is access control") are `partly`; the reasoning goes
  in an annotation on the threat; unsure or blank answers get no property. Deriving the flag from
  ATLAS, OWASP LLM or MAESTRO mappings was rejected, because it contradicts LF AI's own answers.
- **Control tier (2026-10-13):** a control's relationship to threats may use an **optional** second
  custom type, `supports`, alongside `mitigates`: `mitigates` is a direct mitigation (LF AI's
  "Tier 1 – Direct Mitigations") and `supports` a supporting control ("Tier 2 – Supporting
  Controls"). Each type at most once per control, both pointing only at threats. The tier belongs to
  the link, not the control: 14 of the 52 NIST controls LF AI maps are Tier 1 for one threat and
  Tier 2 for another. Nobody has to use `supports`; library models only use `mitigates`. A name
  mentioning risk was rejected because the library does not tie controls to risks. Converting back
  stops with an error for `supports`, as library controls have no tier.
- **Threat layer (2026-10-13):** two kinds of layer, two places.
  - AI system layers (clinician scribe: Model, DataOps, Agent, Deployment, Governance) use
    CycloneDX's native MAESTRO categories in `threat.categories`: `foundation-models`,
    `data-operations`, `agent-frameworks`, `deployment-and-infrastructure`,
    `security-and-compliance`. No schema change.
  - Technology layers (code assistant and chatbot: AI, Application, Platform, Network) use an
    optional, repeatable threat property `org.owasp.threat-model-library.threat-layer`, limited to
    LF AI's layer stack: `ai`, `application`, `platform`, `os-firmware`, `data`, `network`,
    `infrastructure`. A multi-layer threat ("AI / platform") gets one entry per layer. Mapping these
    to MAESTRO was rejected because four of them would merge into `deployment-and-infrastructure`
    and `application` has no MAESTRO equivalent. The layer stack is still a work in progress at
    LF AI, so this list is updated when they finalise it.
- **Attack path steps (2026-10-13):** a step's `source` and `destination` must be references to
  modelled elements (`<prefix>-<name>`), as CycloneDX defines them. LF AI's FromWhere / ToWhere
  values map here; a place that is not modelled (such as "a pastebin or forum post") either becomes
  an asset or actor, or goes in the step's `description`. Nothing is lost, but free text is no
  longer accepted where CycloneDX expects a reference.
- **Code assistant example (2026-10-13):** `lfai-code-assistant-threat-model-cyclonedx-2.0.json`
  models LF AI's code assistant from their sources: 51 threats with scenarios, 36 flows, 3 use cases,
  35 assets (LF AI's components plus information assets A01–A14), 78 controls (52 NIST SP 800-53,
  linked by `mitigates`/`supports` from LF AI's tiers, satisfying NIST and CSA AICM requirements,
  plus C01–C26), STRIDE, CAPEC, CWE, ATLAS and OWASP LLM mappings. LF AI's working text (AI-generated
  CAPEC suggestions, mapping rationales, NIST justifications, notes) is kept verbatim as annotations.
  **Assumed, for LF AI to review** (each marked by an annotation):
  - scope: criticality `high`, data sensitivity intellectual property and credentials, exposure
    `internal`, tier `business_critical`; version `0.1`;
  - control status `recommended`; priority `high` for Tier 1 NIST controls, otherwise `medium`;
  - `encrypted` on the 12 data flows (in-workstation `false`, network `true`);
  - impact level on every scenario (`major` where operations are harmed, otherwise `moderate`);
  - attacker type attributes, and the attacker type of 9 threats whose Actor is blank (from their
    NIST threat source);
  - trust boundaries between Internal and each external zone;
  - the spreadsheet's and tables' "Located In" names, from an older diagram, mapped onto
    `definition.md`'s components.
  Not carried over: LF AI's three `actor:` entries in `components` (they duplicate the actors), and
  7 flows the top-level use case lists but `definition.md` never defines (recorded in an annotation).
  The second T33 becomes `threat-t33b`.
- **Review complete (2026-10-13):** every element of the LF AI code assistant use case (spreadsheet,
  `definition.md`, asset/control/threat tables) and of the chatbot and clinician scribe tables now
  has a home in the schema. The only LF AI data still needing their input is data they have not
  recorded yet: actor titles and zones, scenario events for 24 threats, and impact ratings.

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
