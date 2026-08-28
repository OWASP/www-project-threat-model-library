#!/usr/bin/env python3
"""Deterministic structural/referential/risk-math checks for an OWASP Threat
Model Library JSON file, plus a second tier of HINTS: signals computed from
data already in the file that narrow (but do not replace) a reviewer's
semantic judgment calls (diagram consistency, traceability, chart severity
classification -- see .claude/skills/threat-model-review/SKILL.md).

This script is shared, not skill-private: the threat-model-review Claude
Code skill calls it, and .github/workflows/ CI calls it on every PR that
touches threat-models/**/*.json. Keep it dependency-free (stdlib only) so
it runs the same way in both places without an install step.

Usage: validate_threat_model.py <path-to-threat-model.json>

FINDINGS (ERROR/CRITICAL_GAP/WARN/INFO) have one unambiguous right answer:
does a referenced symbolic_name exist, does a risk's score match its stated
likelihood/impact per the project's 5x5 matrix.

HINTS are best-effort heuristics, not verdicts -- they exist to save a
reviewer from re-deriving mechanical facts by eye, not to replace reading
prose/diagrams. Every hint below has a known failure mode noted in its own
section; treat a hint as a starting point to verify, not a finding to
report verbatim.
"""
import json
import os
import re
import sys

CAPEC_NAMES_PATH = os.path.join(os.path.dirname(__file__), "capec-names.json")

LIKELIHOOD_ORDER = ["rare", "unlikely", "possible", "likely", "certain"]
IMPACT_ORDER = ["negligible", "minor", "moderate", "major", "severe"]

STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "into", "over",
    "via", "not", "are", "all", "its", "a", "an", "of", "in", "on", "to",
    "or", "as", "is",
}

# Curated, intentionally incomplete: only CWEs/CAPECs with one clearly
# dominant chart category are included. Anything not listed here should be
# treated as unmapped -- guessing a category for a weakness that doesn't
# clearly imply one is worse than leaving it to the LLM.
CWE_CATEGORY_HINTS = {
    119: "Unauthorised Access/Privilege Escalation (memory corruption)",
    121: "Unauthorised Access/Privilege Escalation (stack buffer overflow)",
    787: "Unauthorised Access/Privilege Escalation (out-of-bounds write)",
    269: "Unauthorised Access/Privilege Escalation (privilege management)",
    284: "Unauthorised Access/Privilege Escalation (access control)",
    732: "Unauthorised Access/Privilege Escalation (permission assignment)",
    200: "Data Exfiltration/Info Disclosure",
    908: "Data Exfiltration/Info Disclosure (uninitialized resource)",
    203: "Data Exfiltration/Info Disclosure (observable discrepancy)",
    1303: "Data Exfiltration/Info Disclosure (microarchitectural side channel)",
    400: "Denial of Service (resource consumption)",
    770: "Denial of Service (unbounded allocation)",
    15: "Tampering/Integrity (config manipulation)",
    494: "Supply Chain/Dependency (missing integrity check)",
    1277: "Supply Chain/Dependency (firmware not updateable)",
    1328: "Supply Chain/Dependency (mutable security version)",
    638: "Supply Chain/Dependency (altered firmware)",
    682: "Supply Chain/Dependency (unpatchable firmware/ROM)",
}
CAPEC_CATEGORY_HINTS = {
    100: "Unauthorised Access/Privilege Escalation (buffer overflow)",
    480: "Unauthorised Access/Privilege Escalation (escaping virtualization)",
    233: "Unauthorised Access/Privilege Escalation (privilege escalation)",
    180: "Unauthorised Access/Privilege Escalation (misconfigured access control)",
    261: "Data Exfiltration/Info Disclosure (fuzzing for adjacent data)",
    663: "Data Exfiltration/Info Disclosure (transient execution)",
    130: "Denial of Service (excessive allocation)",
    153: "Tampering/Integrity (input data manipulation)",
    176: "Tampering/Integrity (configuration manipulation)",
    554: "Security Feature Bypass (functionality bypass)",
    438: "Supply Chain/Dependency (modification during manufacture)",
}


def level_for_score(score):
    if score <= 2:
        return "very_low"
    if score <= 4:
        return "low"
    if score <= 9:
        return "medium"
    if score <= 12:
        return "high"
    if score <= 16:
        return "very_high"
    return "critical"


def main():
    if len(sys.argv) != 2:
        print("usage: validate_threat_model.py <path-to-threat-model.json>", file=sys.stderr)
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path) as f:
            d = json.load(f)
    except json.JSONDecodeError as e:
        print(f"JSON_PARSE_ERROR: {e}")
        sys.exit(1)

    findings = []  # (severity, message)

    def flag(severity, message):
        findings.append((severity, message))

    try:
        with open(CAPEC_NAMES_PATH) as f:
            capec_names = json.load(f)
    except FileNotFoundError:
        capec_names = {}

    trust_zones = {t["symbolic_name"]: t for t in d.get("trust_zones", [])}
    actors = {a["symbolic_name"]: a for a in d.get("actors", [])}
    components = {c["symbolic_name"]: c for c in d.get("components", [])}
    data_stores = {s["symbolic_name"]: s for s in d.get("data_stores", [])}
    data_sets = {s["symbolic_name"]: s for s in d.get("data_sets", [])}
    threat_personas = {p["symbolic_name"]: p for p in d.get("threat_personas", [])}
    threats = {t["symbolic_name"]: t for t in d.get("threats", [])}
    controls = {c["symbolic_name"]: c for c in d.get("controls", [])}
    risks = {r["symbolic_name"]: r for r in d.get("risks", [])}
    trust_boundary_pairs = {
        frozenset([tb["trust_zone_a"], tb["trust_zone_b"]])
        for tb in d.get("trust_boundaries", [])
    }

    # --- trust_boundaries reference real trust_zones ---
    for tb in d.get("trust_boundaries", []):
        for key in ("trust_zone_a", "trust_zone_b"):
            if tb.get(key) not in trust_zones:
                flag("ERROR", f"trust_boundaries: '{key}'='{tb.get(key)}' does not exist in trust_zones")

    # --- actors/components/data_stores reference real trust_zones ---
    for kind, pool in (("actors", actors), ("components", components), ("data_stores", data_stores)):
        for name, obj in pool.items():
            tz = obj.get("trust_zone")
            if tz not in trust_zones:
                flag("ERROR", f"{kind}.{name}: trust_zone '{tz}' does not exist in trust_zones")

    for name, c in components.items():
        parent = c.get("parent_component")
        if parent and parent not in components:
            flag("ERROR", f"components.{name}: parent_component '{parent}' does not exist in components")

    # --- data_sets placements reference real data_stores ---
    for name, ds in data_sets.items():
        for p in ds.get("placements", []):
            store = p.get("data_store")
            if store and store not in data_stores:
                flag("ERROR", f"data_sets.{name}: placement references unknown data_store '{store}'")

    # --- data_flows source/destination resolve ---
    typed_pools = {
        "component": components,
        "actor": actors,
        "data_store": data_stores,
        "data_set": data_sets,
    }
    for flow in d.get("data_flows", []):
        fname = flow.get("symbolic_name")
        for end in ("source", "destination"):
            ref = flow.get(end, {})
            rtype, robj = ref.get("type"), ref.get("object")
            pool = typed_pools.get(rtype)
            if pool is None:
                flag("ERROR", f"data_flows.{fname}: {end}.type '{rtype}' is not one of component/actor/data_store/data_set")
            elif robj not in pool:
                flag("ERROR", f"data_flows.{fname}: {end} references '{robj}' (type={rtype}) which does not exist")

    # --- threats reference real components_affected / threat_persona ---
    affected_pool = {**components, **data_stores}
    for name, t in threats.items():
        persona = t.get("threat_persona")
        if persona not in threat_personas:
            flag("ERROR", f"threats.{name}: threat_persona '{persona}' does not exist in threat_personas")
        for comp in t.get("components_affected", []) or []:
            if comp not in affected_pool:
                flag("ERROR", f"threats.{name}: components_affected references unknown component/data_store '{comp}'")
        if not t.get("components_affected"):
            flag("WARN", f"threats.{name}: components_affected is empty -- cannot trace this threat to a specific architecture element")
        if not t.get("weaknesses"):
            flag("INFO", f"threats.{name}: no CWE weaknesses listed")
        if not t.get("attack_mechanisms"):
            flag("INFO", f"threats.{name}: no CAPEC attack_mechanisms listed")
        for a in t.get("attack_mechanisms") or []:
            cid, given_title = a.get("capec_id"), a.get("capec_title")
            canonical = capec_names.get(str(cid))
            if canonical is None:
                flag("WARN", f"threats.{name}: capec_id {cid} not found in the bundled CAPEC reference (scripts/capec-names.json) -- may be deprecated/withdrawn, a category/view ID rather than an attack pattern, or a typo; verify manually")
            elif given_title and given_title.strip().lower() != canonical.strip().lower():
                flag("ERROR", f"threats.{name}: capec_title '{given_title}' does not match the canonical name for CAPEC-{cid} ('{canonical}')")

    # --- controls reference real threats; trust_boundary refs valid ---
    for name, c in controls.items():
        for th in c.get("threats", []) or []:
            if th not in threats:
                flag("ERROR", f"controls.{name}: threats references unknown threat '{th}'")
        tb = c.get("trust_boundary")
        if tb:
            a, b = tb.get("trust_zone_a"), tb.get("trust_zone_b")
            if a not in trust_zones or b not in trust_zones:
                flag("ERROR", f"controls.{name}: trust_boundary references unknown trust_zone(s) '{a}'/'{b}'")
            elif frozenset([a, b]) not in trust_boundary_pairs:
                flag("ERROR", f"controls.{name}: trust_boundary {a}<->{b} is not declared in trust_boundaries")

    # --- risks reference real threats; score/level match the 5x5 matrix ---
    for name, r in risks.items():
        for th in r.get("threats", []) or []:
            if th not in threats:
                flag("ERROR", f"risks.{name}: threats references unknown threat '{th}'")
        likelihood, impact = r.get("likelihood"), r.get("impact")
        if likelihood in LIKELIHOOD_ORDER and impact in IMPACT_ORDER:
            expected_score = (LIKELIHOOD_ORDER.index(likelihood) + 1) * (IMPACT_ORDER.index(impact) + 1)
            expected_level = level_for_score(expected_score)
            if r.get("score") != expected_score:
                flag("ERROR", f"risks.{name}: score={r.get('score')} but likelihood={likelihood} x impact={impact} = {expected_score} per the project's 5x5 matrix")
            if r.get("level") != expected_level:
                flag("ERROR", f"risks.{name}: level='{r.get('level')}' but score {r.get('score')} maps to '{expected_level}'")

    # --- critical/high coverage: every threat inside a high/very_high/critical risk must have >=1 control ---
    HIGH_BANDS = {"high", "very_high", "critical"}
    controlled_threats = set()
    for c in controls.values():
        controlled_threats.update(c.get("threats", []) or [])

    risked_threats = set()
    high_risk_threats = {}  # threat_name -> [risk_names]
    for rname, r in risks.items():
        risked_threats.update(r.get("threats", []) or [])
        if r.get("level") in HIGH_BANDS:
            for th in r.get("threats", []) or []:
                high_risk_threats.setdefault(th, []).append(rname)

    for th, risk_names in high_risk_threats.items():
        if th not in controlled_threats:
            flag("CRITICAL_GAP", f"threats.{th}: part of {risk_names} (level in {sorted(HIGH_BANDS)}) but has NO control addressing it")
        else:
            covering = [cn for cn, c in controls.items() if th in (c.get("threats") or [])]
            weak = [cn for cn in covering if controls[cn].get("priority") not in ("high", "critical")]
            if weak and len(weak) == len(covering):
                flag("WARN", f"threats.{th}: part of {risk_names} but all covering controls {covering} have priority < high")

    unrisked = sorted(set(threats) - risked_threats)
    if unrisked:
        flag("INFO", f"{len(unrisked)} threat(s) are not referenced by any risk (severity not formally assessed): {unrisked}")

    uncontrolled = sorted(set(threats) - controlled_threats)
    if uncontrolled:
        flag("INFO", f"{len(uncontrolled)} threat(s) have no control at all: {uncontrolled}")

    # --- controls/risks with no findings at all is itself notable ---
    if not risks:
        flag("WARN", "risks: section is empty or absent -- no threat in this model has a formally assessed likelihood/impact/score/level")
    if not controls:
        flag("WARN", "controls: section is empty or absent -- no threat in this model has a documented mitigation")

    # ============================================================
    # HINTS -- best-effort signals, not verdicts. See module docstring.
    # ============================================================
    hints = []

    def hint(section, message):
        hints.append((section, message))

    # --- traceability: does a threat's own text name its affected component? ---
    for name, t in threats.items():
        affected = t.get("components_affected") or []
        if not affected:
            continue
        text = (t.get("description", "") + " " + t.get("event", "")).lower()
        pool = {**components, **data_stores}
        mentioned = any(
            any(
                word.lower() in text
                for word in re.split(r"[/\s]+", pool[c]["title"])
                if word and word.lower() not in STOPWORDS
            )
            for c in affected if c in pool
        )
        if not mentioned:
            hint("traceability", f"threats.{name}: description/event never names any word from its components_affected's title ({affected}) -- possible generic/boilerplate text, but short acronym-style titles can false-positive here, verify by reading it")

    # --- auth-required signal: persona access_level + adjoining trust_boundary controls ---
    component_tz = {**{c: v["trust_zone"] for c, v in components.items()},
                     **{c: v["trust_zone"] for c, v in data_stores.items()}}
    tz_boundaries = {}
    for tb in d.get("trust_boundaries", []):
        for tz in (tb.get("trust_zone_a"), tb.get("trust_zone_b")):
            tz_boundaries.setdefault(tz, []).append(tb)

    for name, t in threats.items():
        persona_name = t.get("threat_persona")
        persona = threat_personas.get(persona_name)
        if not persona:
            continue
        affected_tzs = {component_tz[c] for c in (t.get("components_affected") or []) if c in component_tz}
        boundaries = [tb for tz in affected_tzs for tb in tz_boundaries.get(tz, [])]
        if not boundaries:
            continue
        # "any", not "all": one open boundary into the zone is enough for an
        # unauthenticated path to exist, even if another boundary into the
        # same zone happens to require e.g. mac. Only emit the positive
        # ("likely No") signal -- silence (no hint) means "couldn't tell",
        # not "Auth Required: Yes". This tool has no data linking a
        # threat_persona to a specific originating trust_zone, so it can't
        # reliably identify the actual attacker-to-target path, only that
        # *an* open path into the target's zone exists somewhere.
        has_open_boundary = any(
            (not tb.get("access_control_methods") or tb["access_control_methods"] == ["none"])
            and (not tb.get("authentication_methods") or tb["authentication_methods"] == ["none"])
            for tb in boundaries
        )
        if persona.get("access_level") in ("anonymous", "user") and has_open_boundary:
            hint("auth-required", f"threats.{name}: persona access_level='{persona['access_level']}' and at least one trust_boundary into its component's zone has no access/auth control -- consistent with 'Auth Required: No' on the severity chart, but confirm this is the actual attack path, and still judge Context/Interaction/Category yourself")

    # --- CWE/CAPEC -> chart category hints ---
    for name, t in threats.items():
        suggestions = set()
        for w in t.get("weaknesses") or []:
            cat = CWE_CATEGORY_HINTS.get(w.get("cwe_id"))
            if cat:
                suggestions.add(cat)
        for a in t.get("attack_mechanisms") or []:
            cat = CAPEC_CATEGORY_HINTS.get(a.get("capec_id"))
            if cat:
                suggestions.add(cat)
        if suggestions:
            hint("chart-category", f"threats.{name}: weaknesses/attack_mechanisms suggest category candidate(s): {sorted(suggestions)} -- confirm against the event text, don't take unmapped CWEs/CAPECs as 'no category'")

    # --- mermaid diagram edge auto-extraction + symbolic-name fast-path match ---
    flow_pairs = {f["symbolic_name"]: (f["source"]["object"], f["destination"]["object"]) for f in d.get("data_flows", [])}
    mermaid_edge_re = re.compile(r'(\w+)\s*(?:--+>|-\.->|==+>)\s*\|?([^|>\n]*)\|?\s*(\w+)')
    for dia in d.get("diagrams", []):
        if dia.get("type") != "mermaid" or not dia.get("source"):
            continue
        edges = mermaid_edge_re.findall(dia["source"])
        auto_matched = 0
        for from_node, label, to_node in edges:
            label = label.strip().strip('"')
            if label in flow_pairs:
                auto_matched += 1
        hint("diagram", f"diagram '{dia.get('title')}': regex found {len(edges)} arrow(s); {auto_matched} had a label exactly matching a data_flows symbolic_name (auto-verified as a fast path). The rest need semantic node-to-component matching by hand -- this extraction is regex-based and can miss multi-line/styled arrows, don't treat its edge count as authoritative.")

    # --- print report ---
    order = {"ERROR": 0, "CRITICAL_GAP": 1, "WARN": 2, "INFO": 3}
    findings.sort(key=lambda x: order.get(x[0], 9))
    if not findings:
        print("No structural, referential, or risk-math issues found.")
    for severity, message in findings:
        print(f"[{severity}] {message}")

    counts = {}
    for severity, _ in findings:
        counts[severity] = counts.get(severity, 0) + 1
    print("\n--- summary ---")
    for sev in ("ERROR", "CRITICAL_GAP", "WARN", "INFO"):
        if sev in counts:
            print(f"{sev}: {counts[sev]}")

    if hints:
        print("\n--- hints (signals for LLM judgment in steps 3-5; not verdicts) ---")
        for section, message in hints:
            print(f"[HINT:{section}] {message}")


if __name__ == "__main__":
    main()
