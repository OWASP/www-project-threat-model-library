# CycloneDX 2.0 threat model profile

A CycloneDX 2.0 representation of OWASP Threat Model Library documents. It carries every field of
[`threat-model.schema.json`](../threat-model.schema.json) with no data loss. This is a proposal:
It has two examples until the schema is agreed: Husky AI, converted from the library, and LF AI & Data's code
assistant, an AI system modelled directly in CycloneDX.

| File | Purpose |
|------|---------|
| `cyclonedx-threat-model-2.0.schema.json` | Source schema. Edit this one. |
| `cyclonedx-threat-model-2.0-bundled.schema.json` | Generated, self-contained schema used for validation. |
| `build-schema.sh` | Regenerates the bundled schema from the pinned CycloneDX fork. |
| `DECISIONS.md` | Why the profile looks the way it does, and the status of the work. |
| `husky-ai-threat-model-cyclonedx-2.0.json` | Example: [Husky AI](../threat-models/ai-ml-systems/husky-ai-threat-model.json), converted. |
| `lfai-code-assistant-threat-model-cyclonedx-2.0.json` | Example: LF AI & Data's [code assistant](https://github.com/lfai/security-and-compliance/tree/main/subgroups/use-cases-and-threat-models/use_cases/code_assistant) use case. CycloneDX only; values LF AI has not recorded are marked as assumed. |
| [`../scripts/cyclonedx_convert.py`](../scripts/cyclonedx_convert.py) | Converts in both directions and checks round trips. |

## Source of the CycloneDX models

The bundled schema is built from
[`P3tra-WP/specification`](https://github.com/P3tra-WP/specification) on branch
`2.0-dev-threatmodeling-library-parity`, at commit `7973584`. The build uses that fork's own
bundler (`tools/src/main/js/bundler`). The SPDX, behaviour taxonomy and cryptography definition
schemas are bundled too, so no `$ref` points outside the file. To move to a newer fork commit,
change `SPEC_COMMIT` in `build-schema.sh` and run it.

## Required elements

The profile is CycloneDX 2.0 plus rules that require everything the library format requires:

- exactly one blueprint, with a scope, version, zones, boundaries, actors, assets (components),
  data stores, data sets and flows, each with its required fields;
- the scope's business criticality, exposure and tier;
- a name for every actor;
- an event and a threat profile for every threat scenario;
- whether each threat profile is a person, its access level and its malicious intent (skill level
  and applicability to the organisation are optional);
- a priority for every control, and `mitigates` relationships that point only at threats;
- a full inherent risk rating for every risk.

Enums are limited to the values the mapping uses, and `bom-ref`s follow the CycloneDX examples: lowercase `<prefix>-<symbolic-name>`
(for example `zone-prod-zone`), so references can always be resolved back. JSON Schema can't
check that a reference points at an object that exists, or that each threat has exactly one
scenario. The converter checks those.

## No data loss

`to_native(to_cyclonedx(doc)) == doc` holds for every native document, and CI checks it on every
library model. When a value has no lossless CycloneDX form, the converter stops with an error rather
than dropping it. The only such case is a trust boundary from a zone to itself, because CycloneDX
boundaries need two distinct zones.

```sh
python3 scripts/cyclonedx_convert.py check threat-models/*/*.json
python3 scripts/cyclonedx_convert.py to-cyclonedx threat-models/ai-ml-systems/husky-ai-threat-model.json
python3 scripts/cyclonedx_convert.py to-native cyclonedx/husky-ai-threat-model-cyclonedx-2.0.json
```

## Mapping

Native values go to a native CycloneDX field when one has the same meaning. When CycloneDX 2.0
has no equivalent, the value goes into a property named `org.owasp.threat-model-library.<name>`
on the closest owning object. "Property" in the table below means that fallback.

| Native | CycloneDX |
|--------|-----------|
| `$schema` | BOM property `source-schema` |
| `version` | `blueprints[0].metadata.ordinalVersion` |
| `scope.title`, `scope.description` | `blueprints[0].scope.name`, `.description` (title also used as blueprint `name`) |
| `scope.business_criticality`, `exposure`, `tier`, `data_sensitivity[]` | scope properties `business-criticality`, `exposure`, `tier`, one `data-sensitivity` per value |
| `description` | `blueprints[0].description` |
| `frozen` | `blueprints[0].metadata.frozen` |
| `reviewed_at` | `metadata.reviewDate` (a date becomes midnight UTC; the original is kept in property `reviewed-at`) |
| `released_at` | `metadata.validityPeriod.start` (a date becomes midnight UTC; the original is kept in property `released-at`) |
| `product_release_date` | blueprint property `product-release-date` |
| `repo_link`, `release_docs_link` | blueprint `externalReferences` of type `vcs`, `release-notes` |
| `diagrams[]` | `visualizations[]`: `title`→`name`, `link`→`url`, `source`→`attachment.content`, `type`→`attachment.mediaType` (`text/vnd.graphviz`, `text/vnd.mermaid`, `text/vnd.plantuml`, `image/svg+xml`) |
| `trust_zones[]` | `zones[]` of type `trust`, bom-ref `zone-<name>` |
| `trust_boundaries[]` | `boundaries[]` of type `trust`, bom-ref `bnd-<a>-<b>`; methods → `crossingRequirements`; token and logout flags → `sessionManagement` |
| `actors[]` | `actors[]`; `type` → `party` (persona archetype, or `system` for `system`); `title` → property `title`; `permissions` → `permissions[0]` |
| `components[]` | `assets[]` of type `component`; `repo_link` → `vcs` external reference; `parent_component` → `relationships[].contains` |
| `data_stores[]` | `dataStores[]`; `sql`→`relational`, `key_value`→`key-value`, `time_series`→`time-series` |
| `data_sets[]` | `dataSets[]`; `data_sensitivity` → a `data-sensitivity` data profile's `informationTypes`; `access_control_methods` → `authorization` |
| `data_flows[]` | `flows[]` of type `data`; `has_sensitive_data` → a `sensitive-data` data profile classified `confidential` |
| `assumptions[]` | `assumptions[]`; `confirmed`/`unconfirmed`/`rejected` → `verified`/`unverified`/`invalid`; one topic → `topic`, otherwise blueprint property `assumption-topics` |
| `threat_personas[]` | `profiles.threatProfiles[]`; `skill_level` → `skillSet[0]` (plus a derived `sophistication`); `is_person`, `access_level`, `malicious_intent`, `applicability_to_org` → properties |
| `threats[]` | `threats.threats[]` plus one `threats.scenarios[]` entry each, which holds `event` and `threat_persona` (`threatProfile`) |
| `threats[].sources` | `origin` (NIST SP 800-30: `adversarial`, `accidental`, `structural`, `environmental`); more or fewer than one source → property `sources` |
| `threats[].attack_mechanisms` | `threats.attackPatterns[]` (`capecId`, `name`), referenced by bom-ref |
| `threats[].weaknesses` | `weaknesses[].cweId`; each title → a `documentation` external reference to the CWE definition page, title in `comment` (a CycloneDX weakness holds a `cweId` or a `name`, never both) |
| `threats[].components_affected` | `affectedAssets` |
| `controls[]` | `controls[]`; `trust_boundary` → `appliesTo`; `priority` → property; `threats` → a blueprint relationship `{"ref": "control-…", "custom": [{"type": "mitigates", "targets": ["threat-…"]}]}` in native order, mirrored as each threat's `mitigations` |
| `controls[].status` | `active`→`implemented`, `suggested`→`recommended`, `under_review`→`proposed`, `scheduled`→`planned`, `retired`→`decommissioned`, `wont_do`→`rejected`, `approved`→`approved`, `assumed`→custom `assumed` |
| `risks[]` | `risks.risks[]`; `description` → `statement`; `threats` → `relatedThreats`; likelihood, impact, `impact_description`, score and level → `inherentRisk` with methodology `qualitative-matrix` |
| `risks[].level` | `riskScore.level`; `very_low` and `very_high` have no CycloneDX level of their own, so they are also kept in property `risk-level` |
| `extensions` | BOM `ext:<domain>:<path>` keys, or property `extension` for values CycloneDX extensions cannot hold |

CycloneDX lists must not contain duplicates. When a native list does, the CycloneDX field gets the
de-duplicated list and the exact original goes into a property named after the native field.

## Beyond the library format

The profile also accepts CycloneDX elements the library format has no field for, added so that LF
AI & Data's threat models fit without loss (decision 18 in [`DECISIONS.md`](DECISIONS.md)). All are
optional, and a document using them is CycloneDX only: the converter refuses to convert it back.

| Element | CycloneDX home |
|---|---|
| Use cases and sub use cases | `definitions.useCases`, referenced from `blueprint.useCases` |
| Control, process and other flow types | `flows[].type`, with `sequence`, `synchronous`, `protocols` |
| Agents, models, MCP servers, data assets | asset `type`, or `componentRef` to a BOM component (zone always required) |
| Structural relationships | `relationships` (`aggregates`, `composes`, `contains`, …) |
| Controls placed on components; supporting controls | `control.appliesTo`; custom `supports` relationship |
| STRIDE, MAESTRO | `threat.categories` |
| MITRE ATLAS and ATT&CK | `ap-atlas-…` / `ap-attack-…` attack patterns with `techniques` |
| OWASP LLM Top 10, IBM AI Risk Atlas, DASF | `documentation` external references on the threat |
| NIST SP 800-53, CSA AICM | `definitions.standards`, linked by `control.satisfies` |
| Who, impact, NIST SP 800-30 | `scenario.actor`, `scenario.impact`, `scenario.event`; justifications as `annotations` |
| AI-specific flag, technology layer | threat properties `ai-specific`, `threat-layer` |
| Attack paths, review notes | `threats.attackPaths`, `annotations` |
