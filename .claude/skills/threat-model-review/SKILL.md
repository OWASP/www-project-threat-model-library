---
name: threat-model-review
description: Review an OWASP Threat Model Library JSON file (threat-models/**/*.json in this repo) for diagram/data-flow consistency, architecture-to-threat traceability, missing severe threats, and control coverage of critical/high threats per the OWASP Threat Modeling project's severity chart. Use when the user asks to review, audit, check, validate, or critique a threat model file, or asks "is this threat model complete/correct". Pass --fix to have the skill apply the fixable categories directly to the file.
---

# Threat Model Review

Reviews a threat model JSON file against `threat-model.schema.json` and the
project's own quality bar (`tab_specification.md`), combining a deterministic
script (exact, unambiguous checks) with your own judgment (checks that
require reading prose and diagrams semantically).

Never fabricate CVE/CAPEC/CWE IDs, component facts, or risk numbers you are
not confident about — if unsure, say so as a finding rather than inventing
a plausible-looking answer. For CAPEC specifically, there's no need to rely
on memory at all: `scripts/capec-names.json` has the canonical name for
559 CAPEC IDs, and the script in step 1 already checks every existing
`capec_title` against it. When drafting a *new* `attack_mechanisms` entry
(step 8), look the ID up in that same file rather than recalling its name.

**Verify non-obvious technical claims online before asserting them, every
time — this isn't optional or only-if-asked.** Any time a finding (a
missing threat in 5a, a drafted threat/control/risk in step 8, or a
traceability rewrite in step 4) depends on a claim about how the real
system actually behaves — not just what's already written in this JSON —
check it against an authoritative external source before writing it down.
Use the model's own `repo_link`/`release_docs_link` first if present, then
the upstream project's own architecture/design docs. Use WebFetch (or `gh`/
`curl` for GitHub repos) directly; you don't need to pause and ask
permission to run a read-only fetch, but you do need to tell the user what
you checked and what it showed — including when it weakens or contradicts
the claim, in which case downgrade or retract the finding instead of
asserting it anyway. This has already changed the outcome once in practice:
a drafted "kata-agent command channel" threat looked solid until checking
Kata's own architecture docs showed cgroup/namespace isolation likely
blocks the premise, and it was retracted in favor of a much smaller,
honestly-hedged `assumptions` entry instead. If you can't find anything
authoritative either way, say that plainly too — "I couldn't confirm or
rule this out" is a valid, honest outcome, not a reason to guess.

## 0. Resolve the target file

- If the user gave a path, use it.
- If the user said "all" or gave a directory, glob `threat-models/**/*.json`
  and review each one in turn (repeat steps 1-5 per file; keep reports
  separate).
- Otherwise, default to whatever `threat-models/**/*.json` files differ from
  `main` on the current branch (`git diff main...HEAD --name-only`). If that
  is empty, ask the user which file to review — do not guess.

## 1. Run the deterministic checker first

```
python3 scripts/validate_threat_model.py <path>
```

This script is shared, not owned by this skill — it also runs in CI on
every PR that touches `threat-models/**/*.json`
(`.github/workflows/validate-threat-models.yaml`), informationally. Don't
copy it into the skill directory; reference it in place so both callers
stay on the same logic.

This does the checks that have exactly one right answer and should never be
re-derived by eye:

- Every `symbolic_name` reference (trust_zone, source/destination, parent_component,
  components_affected, threat_persona, threats-in-controls, threats-in-risks,
  trust_boundary) resolves to an object that actually exists.
- Every risk's `score` and `level` matches its `likelihood` × `impact` per the
  project's published 5×5 matrix (`tab_specification.md`) — a risk can be
  internally miscalculated even when every individual field is schema-valid;
  this has happened in practice in this repo, caught by this exact check.
- Every threat belonging to a risk whose `level` is `high`, `very_high`, or
  `critical` has at least one `control` addressing it (`CRITICAL_GAP`).
- Threats with no control at all, and threats not referenced by any risk at
  all, are surfaced as `INFO` — not automatically failures, but raw material
  for your judgment in step 4.
- Every `attack_mechanisms[].capec_title` matches the canonical name for its
  `capec_id`, checked against `scripts/capec-names.json` (559 entries,
  bundled from the official CAPEC mechanisms list). A `capec_id` with no
  entry there is flagged `WARN`, not `ERROR` — it may be deprecated,
  withdrawn, or a category/view ID rather than a leaf attack pattern, not
  necessarily wrong. This has already caught real, since-fixed mismatches in
  this repo (e.g. a threat once tagged CAPEC-640 as "Memory Inspection,"
  but CAPEC-640's actual name is "Inclusion of Code in Existing Process" —
  a different CAPEC ID fit the threat better and was substituted instead).
  There's no equivalent bundled table for CWE — `cwe_title` mismatches still
  need your own judgment/lookup.

Below the findings, the script also prints `[HINT:...]` lines — signals
computed from data already in the file (does a threat's text name its own
component, does its persona/trust-boundary combination suggest "no auth
required," do its CWE/CAPEC tags suggest a chart category, does a mermaid
diagram's arrows auto-match `data_flows` by symbolic-name label). **These
are starting points, not verdicts** — each one has a stated blind spot in
its own message (e.g. the traceability hint can false-positive on
acronym-style titles, the auth-required hint only fires positively and
stays silent rather than guess when it can't tell). Use them to focus
where you read closely in steps 3-5 instead of re-deriving everything by
eye, but the final call in the report is always yours, made by actually
reading the text/diagram — never report a hint verbatim as a finding.

Treat every `ERROR` and `CRITICAL_GAP` line as a finding to report verbatim
(with your own one-line fix suggestion appended). `WARN`/`INFO` lines feed
into steps 3-5 below rather than being reported standalone.

## 2. Read the file plus reference material

Read the target JSON in full, plus:
- `threat-model.schema.json` — for enum values and structural expectations
  the script doesn't check for (it does referential integrity, not full
  schema validation).
- `tab_specification.md` — for the intent behind each section, especially
  the trust-boundary rule: *"If a trust boundary is not defined then that is
  a threat modeling finding — the root cause of potential threats."*
- `.claude/skills/threat-model-review/resources/owasp-threat-severity-chart.md` — the per-threat severity
  classification used in step 5. Read it in full there; don't rely on
  memory of it.

## 3. Diagram ↔ data_flows consistency

For `mermaid` diagrams, the script's `[HINT:diagram]` line already gives
you an arrow count and how many were auto-verified by exact symbolic-name
label match — that fast-path subset doesn't need re-checking by hand. Its
regex extraction can miss multi-line or unusually-styled arrows though, so
don't treat its count as the full picture for `plantuml`/`graphviz`, or as
a reason to skip the manual pass below entirely.

This is an **edge-by-edge, direction-by-direction** check, not a check that
the right node names appear somewhere. Build two explicit lists before
comparing anything:

1. From `data_flows`: a table of `(symbolic_name, source.object, destination.object)`.
2. From each parseable diagram (`mermaid`/`plantuml`/`graphviz`): a table of
   every arrow as `(from_node, to_node, label/description)`, resolving each
   node to the `actors`/`components`/`data_stores` entry it represents by
   `title` or visible name — **do not assume edge labels are symbolic
   names**; in this repo only `kata-containers` follows that convention,
   others label edges with protocol/human text (`hashicorp-vault`,
   `cryptocurrency-wallet`, `devarmor-jira`) or use aliased node names
   (`husky-ai`'s PlantUML `as ext1` style).

Then, for every row in table 1, find its counterpart in table 2 by matching
resolved endpoints, and explicitly compare `source.object → destination.object`
against `from_node → to_node` — same order, not just same pair. Do this for
every single data_flow; don't sample a few and extrapolate.

- Flag (direction mismatch): endpoints match but the arrow runs the other
  way (e.g. data_flows says A→B, diagram draws B→A).
- Flag (missing from diagram): a `data_flows` entry with no corresponding
  arrow anywhere in the diagram.
- Flag (missing from data_flows): a diagram arrow representing a real data
  crossing between two components/actors/stores that has no `data_flows`
  entry at all.
- Flag (orphaned node): a node in the diagram with no corresponding
  `actors`/`components`/`data_stores` entry, or vice versa.

State your match count plainly in the report, e.g. "9/9 data_flows have a
matching diagram arrow in the same direction" — a bare "looks consistent"
is not acceptable; show the row-by-row result was actually done.

If `type` is `svg` and it's only an external `link` with no real source
(just a comment, as in `kata-containers`'s boundary diagram): say plainly
that this diagram cannot be cross-checked automatically and a manual visual
check against `data_flows` is recommended — do not guess at its contents.

## 4. Architecture → threat traceability

The script's `[HINT:traceability]` lines flag threats whose `description`/
`event` never uses any word from their own `components_affected`'s title —
a decent starting shortlist, but check each one by actually reading it
rather than trusting the flag alone (it's a blunt string match and can
false-positive on short/acronym titles).

For every entry in `threats`, ask: **could a reader point at a specific
fact in this document and say "that's why this is a threat"?** Concretely:

- `components_affected` must be non-empty and resolve to real components
  (the script already flags empty/broken references as `ERROR`/`WARN` —
  build on those, don't re-derive them).
- The threat's `description` and `event` should cite something concrete —
  a component's actual behavior/description, a `data_flow`'s
  `encrypted: false` or `has_sensitive_data: true`, a `trust_boundary`
  with weak `access_control_methods`/`authentication_methods`, a
  `data_sensitivity` tag — not a generic STRIDE-category sentence that
  could apply to any system ("an attacker could gain unauthorized access").
  Contrast a strong example (`virtiofs-file-escape` in the Kata model,
  which names the exact mechanism: virtiofsd resolving guest-supplied
  symlinks outside the shared directory) against a weak one (a threat that
  just restates its own title in passive voice).
- If a `threat_persona` is referenced, check its `skill_level`/`access_level`
  is consistent with the described `event` (e.g. don't pair `script_kid`
  with a threat that requires `expert_engineer`-grade exploitation).
- Per the spec's explicit rule: a `trust_boundary` with no meaningful
  `access_control_methods`/`authentication_methods` (empty, or only
  `"none"`) and no threat in this file referencing the components on either
  side of it is itself a finding — the model may be missing a threat, not
  just missing a control.

## 5. Critical/high threat coverage — including threats the model never wrote down

Not every threat needs a formal `risks` entry — that section is selective by
design, and its absence for a given threat is *not itself a finding*. Two
different severity lenses exist and don't get confused:

- **`risks.level`** (this repo's own 5×5 likelihood×impact matrix, in
  `tab_specification.md`) — a *business risk* score, only meaningful when a
  `risks` entry exists, already math-checked by the script in step 1.
- **The OWASP Threat Modeling project's Threat Severity Chart**
  (`.claude/skills/threat-model-review/resources/owasp-threat-severity-chart.md`, bundled in this skill,
  mirrored from the separate `OWASP/www-project-threat-modeling` repo) — a
  *per-threat* severity classification (Critical/Important/Moderate/Low,
  adapted from the Microsoft SDL Bug Bar) that applies to **every** threat
  regardless of whether it has a risk entry. **This is the chart to use for
  "is this threat critical/high" in this section** — read the full file,
  it's short.

### 5a. Are any severe threats missing from the model entirely?

Using your own security knowledge of this class of system (not just what's
already written down), walk the architecture — every `component`,
`trust_boundary`, `data_flow`, `data_store` — and ask what a competent
threat modeler would expect to find threatening here that isn't in
`threats` at all. Ground every candidate in a specific fact already present
in the model (a component's stated behavior, an unencrypted sensitive
`data_flow`, a weakly-controlled `trust_boundary`, a `data_sensitivity`
tag) — don't propose generic checklist threats with no anchor in this
document's own architecture.

Before finalizing any candidate, verify its technical premise online per
the rule at the top of this file — a candidate that depends on how the
real component actually behaves (not just what this JSON already asserts)
needs that check every time, not just when it seems risky to skip.

Classify each candidate against the severity chart (see 5c for how) and
**only report it as a must-fix finding if it lands at Critical (4) or
Important (3)**. Lower-severity candidates aren't worth the noise — mention
them only in passing if at all.

Report each one as: the missing threat, the architectural fact it's
grounded in, and the chart row/category/level it matches. Be conservative —
a false "you're missing X" is worse than a missed one, so if you're not
confident the mechanism is real for this architecture, say so instead of
asserting it.

### 5b. Do existing severe threats have a control?

Classify **every** entry in `threats` (not only ones already in a `risks`
entry) against the severity chart per 5c. For every threat that lands at
Critical (4) or Important (3), confirm it has at least one `controls` entry
addressing it. Do this for all of them, not just the ones a `risks` entry
happens to already cover — a stakeholder reading only the `risks` table
would never see a gap in a threat nobody formally scored.

Where a `risks` entry also exists for the threat, report both classifications
side by side if they disagree sharply (e.g. chart says Critical but the
business risk is `medium` because likelihood was assessed as low for this
org) — that's worth surfacing as its own note, not silently resolved one way.

For controls that do cover a Critical/Important threat, sanity-check
`priority` and `status` — a threat classified Critical, mitigated only by a
`suggested` (not yet `active`/`approved`) or low-`priority` control, is a
real gap even though the schema is satisfied.

### 5c. How to classify a threat against the chart

The script's `[HINT:auth-required]` and `[HINT:chart-category]` lines give
you a candidate Auth-Required signal and candidate category/categories per
threat, derived from its persona/trust-boundary data and its existing
CWE/CAPEC tags. Both are intentionally one-directional: the auth-required
hint only ever asserts "likely No," staying silent rather than guess when
it can't tell (there's no schema field linking a persona to where it
actually starts from, so it can't always identify the real attack path);
the category hint can suggest multiple candidates or none (an unmapped
CWE/CAPEC means "unknown," not "no category"). Use both as a first pass,
then confirm against the actual event text before committing to a
classification — a candidate missing threat drafted from scratch (5a) has
no CWE/CAPEC yet, so the category hint won't apply to it at all; classify
those from the event text directly.

For each threat (existing or candidate), determine:
- **Context**: almost always `Server / Cloud` for infrastructure/service
  threat models in this repo; use `Client` only if the affected component is
  a browser/desktop/mobile app the way `ephemeral-browser-isolation` or
  `cryptocurrency-wallet`'s GUI/mobile components are; use the Hardware
  table only for physical/OTA/external-device threats.
- **Auth Required**: does the attack path require the attacker to already
  hold valid credentials/session for the *target* being compromised? Derive
  this from the `trust_boundary` crossed (its `access_control_methods`/
  `authentication_methods`) and the `threat_persona.access_level` — note
  that a persona with `user`-level access to its *own* intended scope (e.g.
  a container tenant) attacking *outside* that scope (the host) is still
  "unauthenticated" with respect to the target, per the chart's own
  definition ("no valid credentials or established session" for the system
  being attacked).
- **User Interaction**: does a human victim need to click/open/visit
  something, or does the threat fire without any such action (typical for
  server-side/automated `adversary` or `failure` sources)?
- **Category**: match the threat's `event`/CWE/CAPEC to the chart's
  categories (Unauthorised Access/Privilege Escalation, Data Exfiltration/
  Info Disclosure, Tampering/Integrity, Denial of Service, Spoofing/Identity
  Abuse, Lateral Movement, Supply Chain/Dependency, Security Feature Bypass).
- Look up the matching row's **Level** column for that Context/Auth/
  Interaction/Category combination. Cite which row you matched in the
  report so the classification is checkable, not asserted.

If a threat plausibly matches more than one row, take the higher severity —
the chart itself says a lower-severity class combined with by-design
behaviour to reach a higher-severity outcome should be rated at the higher
class.

## 6. Everything else → room for improvement

Bucket separately (not blocking) findings such as: missing CAPEC/CWE codes,
thin threat/control descriptions, `assumptions` left `unconfirmed` that are
load-bearing for a threat's severity, data_sets missing `encrypted`/
`data_sensitivity`, controls with vague `description`, missing `repo_link`,
stale `reviewed_at`.

## 7. Report

Structure the output as:

```
## Threat Model Review: <scope.title>

### Must-fix (referential errors, risk-math errors, missing severe threats, uncontrolled severe threats)
- [file:symbolic_name] <finding> — suggested fix: <...>

### Diagram / data-flow consistency
<row-by-row match count, then any mismatches>

### Missing threats (5a)
- <candidate threat> — grounded in <architectural fact> — chart classification (row/category) → <Critical/Important> — why

### Traceability
- ...

### Existing threats: severity vs. control coverage (5b)
- ...

### Room for improvement
- ...
```

Cite the JSON path (e.g. `threats.vmm-kernel-vuln-exploit` or
`risks.dos-resource-exhaustion-risk.score`) for every finding so it's
directly navigable in the file.

## 8. Offer fixes (only when you have file-editing tools, e.g. running in
   Claude Code)

After presenting the report, if you have Edit/Write access to this repo:

- If invoked with `--fix`, apply fixes for these categories directly and
  then show a summary of what changed (do not silently apply — always show
  the diff/summary):
  1. **Diagram/data_flows sync** — add missing edges to the diagram source
     (or add a note if the diagram is an external SVG that can't be edited
     here), or add a missing `data_flows` entry the diagram clearly implies.
  2. **Traceability text** — tighten a threat's `description`/`event` to
     name the specific architectural fact it derives from, without
     changing its meaning or inventing new claims.
  3. **Missing severe threats and their coverage** — draft a new `threats`
     entry for a genuine 5a finding (with `components_affected`,
     `threat_persona`, `event`, `sources`, and `weaknesses`/
     `attack_mechanisms` only where you're confident of the mapping), plus
     a `risks` entry carrying your likelihood/impact estimate, plus a
     `controls` entry (status: `suggested`, priority matched to the
     severity). Same treatment for a 5b gap — an existing threat assessed
     as severe with no control gets a draft `controls` entry. All of this
     is clearly a draft for human review, not asserted as already
     implemented or already true.
- Without `--fix`, describe the fix in the report but make no edits — ask
  the user whether to apply them.
- Never invent CVE/CAPEC/CWE identifiers to fill a gap; if you can't map a
  weakness/attack-mechanism confidently, say the mapping needs research
  rather than fabricating one.
- Before writing any drafted threat/control/risk text that depends on how
  the real system behaves, verify it online per the rule at the top of
  this file, and say what you checked — whether you're applying via
  `--fix` or proposing it for the user to approve first. If verification
  weakens or contradicts the draft, revise or drop it rather than
  presenting it anyway; a smaller, honestly-checked fix beats a bigger
  unconfirmed one.
- These are content edits to a shared repo file — after applying, remind
  the user to review and commit deliberately; don't commit on their behalf.
