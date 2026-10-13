#!/usr/bin/env python3
"""Lossless conversion between OWASP Threat Model Library documents
(threat-model.schema.json) and the library's CycloneDX 2.0 profile
(cyclonedx/cyclonedx-threat-model-2.0.schema.json).

Every native field is carried by a native CycloneDX field where one has the
same meaning. Where CycloneDX 2.0 has no equivalent, the value goes into a
CycloneDX property named "org.owasp.threat-model-library.<field>" on the
closest owning object. cyclonedx/README.md has the full mapping table.

to_native(to_cyclonedx(doc)) == doc for every valid native document; the
`check` command asserts exactly that. Values that CycloneDX cannot hold
without loss (for example duplicate entries in a list that CycloneDX
requires to be unique) raise ConversionError instead of being dropped.

Stdlib only, like scripts/validate_threat_model.py, so CI needs no install.

Usage:
  cyclonedx_convert.py to-cyclonedx <threat-model.json> [-o <out.json>]
  cyclonedx_convert.py to-native <cyclonedx.json> [-o <out.json>]
  cyclonedx_convert.py check <threat-model.json>...
"""
import argparse
import json
import re
import sys
import uuid

NS = "org.owasp.threat-model-library."
SCHEMA_URL = ("https://github.com/OWASP/www-project-threat-model-library/blob/main/"
              "cyclonedx/cyclonedx-threat-model-2.0-bundled.schema.json")
TOOL = {
    "type": "application",
    "bom-ref": "tool:owasp-threat-model-library-cyclonedx-convert",
    "name": "OWASP Threat Model Library CycloneDX converter",
    "version": "1.0",
}


class ConversionError(ValueError):
    pass


def invert(mapping):
    inverse = {}
    for native, cdx in mapping.items():
        key = json.dumps(cdx, sort_keys=True)
        if key in inverse:
            raise AssertionError(f"mapping is not injective at {cdx!r}")
        inverse[key] = native
    return inverse


def lookup(inverse, cdx, what):
    try:
        return inverse[json.dumps(cdx, sort_keys=True)]
    except KeyError:
        raise ConversionError(f"no native {what} for CycloneDX value {cdx!r}") from None


# Native enum -> CycloneDX enum. Each map is injective so it can be reversed;
# a {"name": ...} value is the CycloneDX "custom" option of that enum.
AUTHENTICATION = {
    "none": "none",
    "password": {"name": "password"},
    "otp": {"name": "otp"},
    "challenge_response": {"name": "challenge-response"},
    "public_key": {"name": "public-key"},
    "token": "bearer",
    "biometrics": "biometric",
    "sso": {"name": "sso"},
    "social": {"name": "social"},
}
AUTHORIZATION = {m: m for m in ("none", "acl", "rbac", "mac", "dac", "abac")}
DATA_STORE_TYPE = {
    "sql": "relational",
    "key_value": "key-value",
    "document": "document",
    "object": "object",
    "graph": "graph",
    "time_series": "time-series",
}
INFORMATION_TYPE = {
    "pii": "pii",
    "phi": "phi",
    "fin": "financial",
    "ip": "intellectual-property",
    "cred": "credentials",
    "biz": {"name": "business"},
    "gov": {"name": "government"},
    "pci": "pci",
    "op": "operational",
}
DIAGRAM_MEDIA_TYPE = {
    "graphviz": "text/vnd.graphviz",
    "mermaid": "text/vnd.mermaid",
    "plantuml": "text/vnd.plantuml",
    "svg": "image/svg+xml",
}
ACTOR_PARTY = {
    "system": {"roles": [{"name": "system"}], "system": {"kind": "software-system"}},
    "user": {"roles": [{"role": "end-user"}], "persona": {"archetype": "end-user"}},
    "power_user": {"roles": [{"role": "end-user"}], "persona": {"archetype": "power-user"}},
    "administrator": {"roles": [{"role": "operator"}], "persona": {"archetype": "administrator"}},
    "engineer": {"roles": [{"role": "engineer"}], "persona": {"archetype": "developer"}},
    "third_party": {"roles": [{"role": "supplier"}], "persona": {"archetype": "third-party"}},
}
ASSUMPTION_VALIDITY = {"unconfirmed": "unverified", "confirmed": "verified", "rejected": "invalid"}
ASSUMPTION_TOPICS = {"availability", "business", "compliance", "operational", "performance", "security", "technical"}
THREAT_SOURCE = {  # NIST SP 800-30 threat source types, both sides
    "adversary": "adversarial",
    "human_error": "accidental",
    "failure": "structural",
    "events_beyond_org_control": "environmental",
}
CONTROL_STATUS = {
    "assumed": {"name": "assumed"},
    "active": "implemented",
    "suggested": "recommended",
    "under_review": "proposed",
    "approved": "approved",
    "scheduled": "planned",
    "retired": "decommissioned",
    "wont_do": "rejected",
}
LIKELIHOOD = {"rare": "very-low", "unlikely": "low", "possible": "medium", "likely": "high", "certain": "certain"}
IMPACT = {"negligible": "negligible", "minor": "low", "moderate": "moderate", "major": "major", "severe": "catastrophic"}
# CycloneDX has five risk levels to the library's six; very_low and very_high
# share a level with a neighbour and are kept exactly in a property.
RISK_LEVEL = {"very_low": "low", "low": "low", "medium": "medium", "high": "high", "very_high": "high", "critical": "critical"}
RISK_LEVEL_EXACT = {"low": "low", "medium": "medium", "high": "high", "critical": "critical", "info": "very_low"}
SESSION_MANAGEMENT = {
    "access_token_expires": "accessTokenExpires",
    "access_token_ttl": "accessTokenTtl",
    "has_refresh_token": "refreshToken",
    "refresh_token_expires": "refreshTokenExpires",
    "refresh_token_ttl": "refreshTokenTtl",
    "can_user_logout": "userLogout",
    "can_system_logout": "systemLogout",
}

# Derived, one-way enrichments for CycloneDX consumers. The native value is
# kept elsewhere and these are ignored on the way back.
SCENARIO_ACCESS_LEVEL = {"anonymous": "external", "user": "internal", "admin": "privileged"}
SOPHISTICATION = {
    "script_kid": "minimal",
    "engineer": "intermediate",
    "expert_engineer": "expert",
    "oc_sponsored": "advanced",
    "state_sponsored": "expert",
}

AUTHENTICATION_REV = invert(AUTHENTICATION)
AUTHORIZATION_REV = invert(AUTHORIZATION)
DATA_STORE_TYPE_REV = invert(DATA_STORE_TYPE)
INFORMATION_TYPE_REV = invert(INFORMATION_TYPE)
DIAGRAM_MEDIA_TYPE_REV = invert(DIAGRAM_MEDIA_TYPE)
ASSUMPTION_VALIDITY_REV = invert(ASSUMPTION_VALIDITY)
THREAT_SOURCE_REV = invert(THREAT_SOURCE)
CONTROL_STATUS_REV = invert(CONTROL_STATUS)
LIKELIHOOD_REV = invert(LIKELIHOOD)
IMPACT_REV = invert(IMPACT)
SESSION_MANAGEMENT_REV = {v: k for k, v in SESSION_MANAGEMENT.items()}
ARCHETYPE_REV = {p["persona"]["archetype"]: t for t, p in ACTOR_PARTY.items() if "persona" in p}

SENSITIVE_DATA_PROFILE = {"name": "sensitive-data", "classification": "confidential"}
DATA_SENSITIVITY_PROFILE = "data-sensitivity"
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
EXT_KEY = re.compile(r"^ext:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:.+$")
CWE_TITLE = re.compile(r"^CWE-(\d+): (.*)$", re.DOTALL)
CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"


# --- helpers ----------------------------------------------------------------

def ref(kind, name):
    return f"{kind}:{name}"


def unref(kind, value):
    prefix = kind + ":"
    if not value.startswith(prefix):
        raise ConversionError(f"expected a {kind} reference, got {value!r}")
    return value[len(prefix):]


def boundary_ref(a, b):
    # Symbolic names cannot contain ':', so this splits back unambiguously.
    return f"trust-boundary:{a}:{b}"


def unboundary_ref(value):
    a, b = unref("trust-boundary", value).split(":")
    return {"trust_zone_a": a, "trust_zone_b": b}


def prop(name, value):
    return {"name": NS + name, "value": value}


def props_of(obj, name):
    return [p.get("value") for p in obj.get("properties", []) if p["name"] == NS + name]


def prop_of(obj, name):
    values = props_of(obj, name)
    return values[0] if values else None


def unique(values, what):
    seen = [json.dumps(v, sort_keys=True) for v in values]
    if len(set(seen)) != len(seen):
        raise ConversionError(f"{what} has duplicate entries, which CycloneDX does not allow: {values!r}")
    return values


def dedupe(values, props, name):
    """CycloneDX lists must be unique; keep the native list verbatim if it was not."""
    out = []
    for v in values:
        if v not in out:
            out.append(v)
    if out != values:
        props.append(prop(name, json.dumps(values)))
    return out


def verbatim(obj, name, fallback):
    value = prop_of(obj, name)
    return json.loads(value) if value is not None else fallback


def to_datetime(value):
    """Return an RFC 3339 date-time for a native date or date-time."""
    if RFC3339.match(value):
        return value
    if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return value + "T00:00:00Z"
    return value + "Z"


def typed_ref(target, owner, end, props):
    """Native typed-symbolic-name -> bom-ref, keeping the exact type string."""
    kind = target["type"].removeprefix("#/$defs/").replace("_", "-")
    if target["type"] != kind.replace("-", "_"):
        props.append(prop(f"{end}-type", target["type"]))
    return ref(kind, target["object"])


def untyped_ref(value, owner, end):
    kind, _, name = value.partition(":")
    return {"type": prop_of(owner, f"{end}-type") or kind.replace("-", "_"), "object": name}


def put(target, key, value):
    if value is not None:
        target[key] = value


def drop_empty_properties(obj):
    if "properties" in obj and not obj["properties"]:
        del obj["properties"]
    return obj


def extension_value_ok(value):
    if isinstance(value, dict):
        return isinstance(value.get("$schema"), str)
    if isinstance(value, list):
        return all(extension_value_ok(v) for v in value)
    return True


# --- native -> CycloneDX ----------------------------------------------------

def to_cyclonedx(tm):
    bom_props = []
    bp_props = []
    scope = tm["scope"]

    scope_props = [prop("business-criticality", scope["business_criticality"])]
    scope_props += [prop("data-sensitivity", s) for s in scope["data_sensitivity"]]
    scope_props += [prop("exposure", scope["exposure"]), prop("tier", scope["tier"])]

    metadata = {"ordinalVersion": tm["version"]}
    put(metadata, "frozen", tm.get("frozen"))
    if "reviewed_at" in tm:
        metadata["reviewDate"] = to_datetime(tm["reviewed_at"])
        if metadata["reviewDate"] != tm["reviewed_at"]:
            bp_props.append(prop("reviewed-at", tm["reviewed_at"]))
    if "released_at" in tm:
        metadata["validityPeriod"] = {"start": to_datetime(tm["released_at"])}
        if metadata["validityPeriod"]["start"] != tm["released_at"]:
            bp_props.append(prop("released-at", tm["released_at"]))
    if "product_release_date" in tm:
        bp_props.append(prop("product-release-date", tm["product_release_date"]))

    bp = {
        "bom-ref": "blueprint",
        "name": scope["title"],
        "modelTypes": ["architecture", "data-flow"],
        "scope": {"name": scope["title"], "description": scope["description"], "properties": scope_props},
        "metadata": metadata,
    }
    put(bp, "description", tm.get("description"))

    if "diagrams" in tm:
        bp["visualizations"] = []
        for d in tm["diagrams"]:
            v = {"name": d["title"], "type": {"type": "architecture"},
                 "attachment": {"mediaType": DIAGRAM_MEDIA_TYPE[d["type"]], "content": d["source"]}}
            put(v, "description", d.get("description"))
            put(v, "url", d.get("link"))
            bp["visualizations"].append(v)

    bp["zones"] = [{"bom-ref": ref("trust-zone", z["symbolic_name"]), "name": z["title"],
                    "description": z["description"], "type": "trust"} for z in tm["trust_zones"]]

    bp["boundaries"] = []
    for tb in tm["trust_boundaries"]:
        a, b = tb["trust_zone_a"], tb["trust_zone_b"]
        if a == b:
            raise ConversionError(f"trust boundary from {a!r} to itself; CycloneDX boundaries need two distinct zones")
        boundary = {"bom-ref": boundary_ref(a, b), "type": "trust", "zones": [ref("trust-zone", a), ref("trust-zone", b)]}
        crossing, boundary_props = {}, []
        if "authentication_methods" in tb:
            crossing["authentication"] = [AUTHENTICATION[m] for m in dedupe(tb["authentication_methods"], boundary_props, "authentication-methods")]
        if "access_control_methods" in tb:
            crossing["authorization"] = [AUTHORIZATION[m] for m in dedupe(tb["access_control_methods"], boundary_props, "access-control-methods")]
        if crossing:
            boundary["crossingRequirements"] = crossing
        session = {SESSION_MANAGEMENT[k]: v for k, v in tb.items() if k in SESSION_MANAGEMENT}
        if session:
            boundary["sessionManagement"] = session
        boundary["properties"] = boundary_props
        bp["boundaries"].append(drop_empty_properties(boundary))
    unique([b["bom-ref"] for b in bp["boundaries"]], "trust_boundaries")

    bp["actors"] = []
    for a in tm["actors"]:
        actor = {"bom-ref": ref("actor", a["symbolic_name"]), "party": json.loads(json.dumps(ACTOR_PARTY[a["type"]])),
                 "description": a["description"], "zone": ref("trust-zone", a["trust_zone"]),
                 "properties": [prop("title", a["title"])]}
        if "permissions" in a:
            actor["permissions"] = [a["permissions"]]
        bp["actors"].append(actor)

    bp["assets"] = []
    children = {}
    for c in tm["components"]:
        asset = {"bom-ref": ref("component", c["symbolic_name"]), "type": "component", "name": c["title"],
                 "description": c["description"], "zone": ref("trust-zone", c["trust_zone"])}
        if "repo_link" in c:
            asset["externalReferences"] = [{"type": "vcs", "url": c["repo_link"]}]
        if "parent_component" in c:
            children.setdefault(c["parent_component"], []).append(asset["bom-ref"])
        bp["assets"].append(asset)
    if children:
        bp["relationships"] = [{"ref": ref("component", p), "contains": kids} for p, kids in children.items()]

    bp["dataStores"] = []
    for s in tm["data_stores"]:
        store = {"bom-ref": ref("data-store", s["symbolic_name"]), "name": s["title"],
                 "description": s["description"], "type": DATA_STORE_TYPE[s["type"]]}
        put(store, "vendor", s.get("vendor"))
        put(store, "product", s.get("product"))
        store["zone"] = ref("trust-zone", s["trust_zone"])
        bp["dataStores"].append(store)

    bp["dataSets"] = []
    for s in tm["data_sets"]:
        data_set = {"bom-ref": ref("data-set", s["symbolic_name"]), "name": s["title"], "description": s["description"]}
        set_props = []
        placements = []
        for p in dedupe(s["placements"], set_props, "placements"):
            if "data_store" not in p:
                raise ConversionError(f"data set {s['symbolic_name']!r} has a placement without data_store")
            placement = {"dataStore": ref("data-store", p["data_store"])}
            put(placement, "encrypted", p.get("encrypted"))
            placements.append(placement)
        data_set["placements"] = placements
        sensitivity = dedupe(s["data_sensitivity"], set_props, "data-sensitivity")
        if sensitivity:
            data_set["dataProfiles"] = [{"name": DATA_SENSITIVITY_PROFILE,
                                         "informationTypes": [INFORMATION_TYPE[x] for x in sensitivity]}]
        if "access_control_methods" in s:
            data_set["authorization"] = [AUTHORIZATION[m] for m in dedupe(s["access_control_methods"], set_props, "access-control-methods")]
        put(data_set, "recordCount", s.get("record_count"))
        data_set["properties"] = set_props
        bp["dataSets"].append(drop_empty_properties(data_set))

    bp["flows"] = []
    for f in tm["data_flows"]:
        flow_props = []
        flow = {"bom-ref": ref("data-flow", f["symbolic_name"]), "name": f["title"], "description": f["description"],
                "type": "data",
                "source": typed_ref(f["source"], f, "source", flow_props),
                "destination": typed_ref(f["destination"], f, "destination", flow_props),
                "encrypted": f["encrypted"]}
        if f["has_sensitive_data"]:
            flow["dataProfiles"] = [dict(SENSITIVE_DATA_PROFILE)]
        flow["properties"] = flow_props
        bp["flows"].append(drop_empty_properties(flow))

    if "assumptions" in tm:
        bp["assumptions"] = []
        for i, a in enumerate(tm["assumptions"], 1):
            assumption = {"bom-ref": f"assumption:{i}", "description": a["description"],
                          "validity": ASSUMPTION_VALIDITY[a["validity"]]}
            topics = a.get("topics")
            if topics:
                first = topics[0]
                assumption["topic"] = first if first in ASSUMPTION_TOPICS else {"name": first}
            if topics is not None and len(topics) != 1:
                # The CycloneDX assumption has one topic and no properties.
                bp_props.append(prop("assumption-topics", json.dumps({"assumption": assumption["bom-ref"], "topics": topics})))
            bp["assumptions"].append(assumption)

    bp["properties"] = bp_props
    drop_empty_properties(bp)

    bom = {
        "$schema": SCHEMA_URL,
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, NS + json.dumps(tm, sort_keys=True))),
        "version": 1,
        "metadata": {"tools": {"components": [dict(TOOL)]}},
    }

    vcs = []
    if "repo_link" in tm:
        vcs.append({"type": "vcs", "url": tm["repo_link"]})
    if "release_docs_link" in tm:
        vcs.append({"type": "release-notes", "url": tm["release_docs_link"]})
    if vcs:
        bp["externalReferences"] = vcs
    bom["blueprints"] = [bp]

    personas = {p["symbolic_name"]: p for p in tm.get("threat_personas", [])}
    if "threat_personas" in tm:
        profiles = []
        for p in tm["threat_personas"]:
            profile = {"bom-ref": ref("threat-persona", p["symbolic_name"]), "name": p["title"],
                       "description": p["description"]}
            put(profile, "sophistication", SOPHISTICATION.get(p["skill_level"]))
            profile["skillSet"] = [p["skill_level"]]
            profile["properties"] = [
                prop("is-person", json.dumps(p["is_person"])),
                prop("access-level", p["access_level"]),
                prop("malicious-intent", json.dumps(p["malicious_intent"])),
                prop("applicability-to-org", p["applicability_to_org"]),
            ]
            profiles.append(profile)
        bom["profiles"] = {"threatProfiles": profiles}

    controls = tm.get("controls", [])
    threat_names = [t["symbolic_name"] for t in tm.get("threats", [])]
    mitigations = {name: [] for name in threat_names}
    for c in controls:
        for name in c["threats"]:
            control_ref = ref("control", c["symbolic_name"])
            if name in mitigations and control_ref not in mitigations[name]:
                mitigations[name].append(control_ref)

    if "threats" in tm:
        section_props = []
        patterns = {}
        threats, scenarios = [], []
        for t in tm["threats"]:
            threat_props = []
            threat = {"bom-ref": ref("threat", t["symbolic_name"]), "name": t["title"], "description": t["description"]}
            sources = t["sources"]
            if sources:
                threat["origin"] = THREAT_SOURCE[sources[0]]
            if len(sources) != 1:
                threat_props.append(prop("sources", json.dumps(sources)))
            if "attack_mechanisms" in t:
                refs = []
                for m in dedupe(t["attack_mechanisms"], threat_props, "attack-mechanisms"):
                    key = (m["capec_id"], m.get("capec_title"))
                    if key not in patterns:
                        same_id = sum(1 for k in patterns if k[0] == key[0])
                        pattern_ref = f"capec:{key[0]}" + (f":{same_id + 1}" if same_id else "")
                        patterns[key] = {"bom-ref": pattern_ref, "capecId": key[0], "name": key[1] or f"CAPEC-{key[0]}"}
                        if key[1] is None:
                            section_props.append(prop("untitled-attack-pattern", pattern_ref))
                    refs.append(patterns[key]["bom-ref"])
                threat["attackPatterns"] = unique(refs, "attack_mechanisms")
            if "weaknesses" in t:
                weaknesses = []
                for w in t["weaknesses"]:
                    if all(w["cwe_id"] != kept["cwe_id"] for kept in weaknesses):
                        weaknesses.append(w)
                if weaknesses != t["weaknesses"]:
                    threat_props.append(prop("weaknesses", json.dumps(t["weaknesses"])))
                threat["weaknesses"] = [{"cweId": w["cwe_id"]} for w in weaknesses]
                # A CycloneDX weakness holds a cweId or a name, never both, so
                # the title rides on a link to the CWE definition instead.
                cwe_links = [{"type": "documentation", "url": CWE_URL.format(w["cwe_id"]),
                              "comment": f"CWE-{w['cwe_id']}: {w['cwe_title']}"}
                             for w in weaknesses if "cwe_title" in w]
                if cwe_links:
                    threat["externalReferences"] = cwe_links
            if "components_affected" in t:
                threat["affectedAssets"] = [ref("component", c) for c in dedupe(t["components_affected"], threat_props, "components-affected")]
            if mitigations.get(t["symbolic_name"]):
                threat["mitigations"] = mitigations[t["symbolic_name"]]
            threat["properties"] = threat_props
            threats.append(drop_empty_properties(threat))

            scenario = {"bom-ref": ref("scenario", t["symbolic_name"]), "name": t["title"], "event": t["event"],
                        "threats": [threat["bom-ref"]], "threatProfile": ref("threat-persona", t["threat_persona"])}
            persona = personas.get(t["threat_persona"])
            if persona:
                scenario["accessLevel"] = SCENARIO_ACCESS_LEVEL[persona["access_level"]]
            scenarios.append(scenario)
        unique(threat_names, "threat symbolic names")
        bom["threats"] = {"threats": threats, "scenarios": scenarios, "attackPatterns": list(patterns.values())}
        if section_props:
            bom["threats"]["properties"] = section_props

    if "controls" in tm:
        bom["controls"] = []
        for c in controls:
            control_ref = ref("control", c["symbolic_name"])
            control = {"bom-ref": control_ref, "name": c["title"], "description": c["description"],
                       "status": CONTROL_STATUS[c["status"]]}
            if "trust_boundary" in c:
                control["appliesTo"] = [boundary_ref(c["trust_boundary"]["trust_zone_a"], c["trust_boundary"]["trust_zone_b"])]
            control["properties"] = [prop("priority", c["priority"])]
            # A CycloneDX control cannot name the threats it mitigates, so the
            # link starts from the control as a custom blueprint relationship,
            # in native order. threat.mitigations carries the reverse view.
            targets = dedupe(c["threats"], control["properties"], "threats")
            if targets:
                bp.setdefault("relationships", []).append(
                    {"ref": control_ref, "custom": [{"type": "mitigates", "targets": [ref("threat", t) for t in targets]}]})
            bom["controls"].append(control)

    if "risks" in tm:
        risks = []
        for r in tm["risks"]:
            risk_props = []
            risk = {"bom-ref": ref("risk", r["symbolic_name"]), "name": r["title"], "statement": r["description"],
                    "relatedThreats": [ref("threat", t) for t in dedupe(r["threats"], risk_props, "threats")],
                    "inherentRisk": {
                        "likelihood": {"level": LIKELIHOOD[r["likelihood"]]},
                        "impact": {"level": IMPACT[r["impact"]], "description": r["impact_description"]},
                        "score": {"level": RISK_LEVEL[r["level"]], "score": r["score"], "methodology": "qualitative-matrix"},
                    }}
            if RISK_LEVEL_EXACT.get(RISK_LEVEL[r["level"]]) != r["level"]:
                risk_props.append(prop("risk-level", r["level"]))
            risk["properties"] = risk_props
            risks.append(drop_empty_properties(risk))
        bom["risks"] = {"risks": risks}

    if "$schema" in tm:
        bom_props.append(prop("source-schema", tm["$schema"]))
    if "extensions" in tm:
        if not tm["extensions"]:
            bom_props.append(prop("extensions", "{}"))
        for key, value in tm["extensions"].items():
            domain, path = key.split("/", 1)
            ext_key = f"ext:{domain}:/{path}"
            if EXT_KEY.match(ext_key) and extension_value_ok(value):
                bom[ext_key] = value
            else:
                bom_props.append(prop("extension", json.dumps({"key": key, "value": value})))
    if bom_props:
        bom["properties"] = bom_props
    return bom


# --- CycloneDX -> native ----------------------------------------------------

def to_native(bom):
    if len(bom.get("blueprints", [])) != 1:
        raise ConversionError("expected exactly one blueprint")
    bp = bom["blueprints"][0]
    tm = {}
    put(tm, "$schema", prop_of(bom, "source-schema"))
    metadata = bp.get("metadata", {})
    tm["version"] = metadata["ordinalVersion"]

    scope = bp["scope"]
    tm["scope"] = {
        "title": scope["name"],
        "description": scope["description"],
        "business_criticality": prop_of(scope, "business-criticality"),
        "data_sensitivity": props_of(scope, "data-sensitivity"),
        "exposure": prop_of(scope, "exposure"),
        "tier": prop_of(scope, "tier"),
    }
    put(tm, "description", bp.get("description"))
    put(tm, "frozen", metadata.get("frozen"))
    if "validityPeriod" in metadata:
        tm["released_at"] = prop_of(bp, "released-at") or metadata["validityPeriod"]["start"]
    put(tm, "product_release_date", prop_of(bp, "product-release-date"))
    for ext_ref in bp.get("externalReferences", []):
        if ext_ref["type"] == "release-notes":
            tm.setdefault("release_docs_link", ext_ref["url"])
    if "reviewDate" in metadata:
        tm["reviewed_at"] = prop_of(bp, "reviewed-at") or metadata["reviewDate"]
    for ext_ref in bp.get("externalReferences", []):
        if ext_ref["type"] == "vcs":
            tm.setdefault("repo_link", ext_ref["url"])

    if "visualizations" in bp:
        tm["diagrams"] = []
        for v in bp["visualizations"]:
            d = {"title": v["name"]}
            put(d, "description", v.get("description"))
            put(d, "link", v.get("url"))
            d["type"] = lookup(DIAGRAM_MEDIA_TYPE_REV, v["attachment"]["mediaType"], "diagram type")
            d["source"] = v["attachment"]["content"]
            tm["diagrams"].append(d)

    tm["trust_zones"] = [{"symbolic_name": unref("trust-zone", z["bom-ref"]), "title": z["name"],
                          "description": z["description"]} for z in bp.get("zones", [])]

    tm["trust_boundaries"] = []
    for b in bp.get("boundaries", []):
        zone_a, zone_b = (unref("trust-zone", z) for z in b["zones"])
        tb = {"trust_zone_a": zone_a, "trust_zone_b": zone_b}
        crossing = b.get("crossingRequirements", {})
        if "authorization" in crossing:
            tb["access_control_methods"] = verbatim(b, "access-control-methods", [
                lookup(AUTHORIZATION_REV, m, "access control method") for m in crossing["authorization"]])
        if "authentication" in crossing:
            tb["authentication_methods"] = verbatim(b, "authentication-methods", [
                lookup(AUTHENTICATION_REV, m, "authentication method") for m in crossing["authentication"]])
        for key, value in b.get("sessionManagement", {}).items():
            tb[SESSION_MANAGEMENT_REV[key]] = value
        tm["trust_boundaries"].append(tb)

    tm["actors"] = []
    for a in bp.get("actors", []):
        party = a["party"]
        actor_type = "system" if "system" in party else ARCHETYPE_REV[party["persona"]["archetype"]]
        actor = {"symbolic_name": unref("actor", a["bom-ref"]), "title": prop_of(a, "title"),
                 "description": a["description"], "type": actor_type}
        if "permissions" in a:
            actor["permissions"] = a["permissions"][0]
        actor["trust_zone"] = unref("trust-zone", a["zone"])
        tm["actors"].append(actor)

    parents, mitigated = {}, {}
    for rel in bp.get("relationships", []):
        for child in rel.get("contains", []):
            parents[child] = unref("component", rel["ref"])
        for custom in rel.get("custom", []):
            if custom["type"] == "mitigates":
                mitigated[rel["ref"]] = [unref("threat", t) for t in custom["targets"]]
    tm["components"] = []
    for c in bp.get("assets", []):
        component = {"symbolic_name": unref("component", c["bom-ref"]), "title": c["name"], "description": c["description"]}
        put(component, "parent_component", parents.get(c["bom-ref"]))
        component["trust_zone"] = unref("trust-zone", c["zone"])
        for ext_ref in c.get("externalReferences", []):
            if ext_ref["type"] == "vcs":
                component.setdefault("repo_link", ext_ref["url"])
        tm["components"].append(component)

    tm["data_stores"] = []
    for s in bp.get("dataStores", []):
        store = {"symbolic_name": unref("data-store", s["bom-ref"]), "title": s["name"], "description": s["description"],
                 "type": lookup(DATA_STORE_TYPE_REV, s["type"], "data store type")}
        put(store, "vendor", s.get("vendor"))
        put(store, "product", s.get("product"))
        store["trust_zone"] = unref("trust-zone", s["zone"])
        tm["data_stores"].append(store)

    tm["data_sets"] = []
    for s in bp.get("dataSets", []):
        data_set = {"symbolic_name": unref("data-set", s["bom-ref"]), "title": s["name"], "description": s["description"]}
        placements = []
        for p in s.get("placements", []):
            placement = {"data_store": unref("data-store", p["dataStore"])}
            put(placement, "encrypted", p.get("encrypted"))
            placements.append(placement)
        data_set["placements"] = verbatim(s, "placements", placements)
        data_set["data_sensitivity"] = verbatim(s, "data-sensitivity", [
            lookup(INFORMATION_TYPE_REV, x, "data sensitivity")
            for profile in s.get("dataProfiles", []) if profile.get("name") == DATA_SENSITIVITY_PROFILE
            for x in profile.get("informationTypes", [])])
        if "authorization" in s:
            data_set["access_control_methods"] = verbatim(s, "access-control-methods", [
                lookup(AUTHORIZATION_REV, m, "access control method") for m in s["authorization"]])
        put(data_set, "record_count", s.get("recordCount"))
        tm["data_sets"].append(data_set)

    tm["data_flows"] = []
    for f in bp.get("flows", []):
        tm["data_flows"].append({
            "symbolic_name": unref("data-flow", f["bom-ref"]), "title": f["name"], "description": f["description"],
            "source": untyped_ref(f["source"], f, "source"),
            "destination": untyped_ref(f["destination"], f, "destination"),
            "has_sensitive_data": bool(f.get("dataProfiles")),
            "encrypted": f["encrypted"],
        })

    if "assumptions" in bp:
        topics_by_ref = {}
        for value in props_of(bp, "assumption-topics"):
            entry = json.loads(value)
            topics_by_ref[entry["assumption"]] = entry["topics"]
        tm["assumptions"] = []
        for a in bp["assumptions"]:
            assumption = {"description": a["description"]}
            if a["bom-ref"] in topics_by_ref:
                assumption["topics"] = topics_by_ref[a["bom-ref"]]
            elif "topic" in a:
                topic = a["topic"]
                assumption["topics"] = [topic["name"] if isinstance(topic, dict) else topic]
            assumption["validity"] = lookup(ASSUMPTION_VALIDITY_REV, a["validity"], "assumption validity")
            tm["assumptions"].append(assumption)

    if "threatProfiles" in bom.get("profiles", {}):
        tm["threat_personas"] = [{
            "symbolic_name": unref("threat-persona", p["bom-ref"]), "title": p["name"], "description": p["description"],
            "is_person": json.loads(prop_of(p, "is-person")),
            "skill_level": p["skillSet"][0],
            "access_level": prop_of(p, "access-level"),
            "malicious_intent": json.loads(prop_of(p, "malicious-intent")),
            "applicability_to_org": prop_of(p, "applicability-to-org"),
        } for p in bom["profiles"]["threatProfiles"]]

    section = bom.get("threats")
    if section is not None:
        patterns = {p["bom-ref"]: p for p in section.get("attackPatterns", [])}
        untitled = set(props_of(section, "untitled-attack-pattern"))
        scenarios = {s["threats"][0]: s for s in section.get("scenarios", [])}
        tm["threats"] = []
        for t in section.get("threats", []):
            scenario = scenarios[t["bom-ref"]]
            threat = {"symbolic_name": unref("threat", t["bom-ref"]), "title": t["name"], "description": t["description"]}
            if "affectedAssets" in t:
                threat["components_affected"] = verbatim(t, "components-affected", [unref("component", c) for c in t["affectedAssets"]])
            threat["threat_persona"] = unref("threat-persona", scenario["threatProfile"])
            threat["event"] = scenario["event"]
            sources = prop_of(t, "sources")
            threat["sources"] = json.loads(sources) if sources is not None else [lookup(THREAT_SOURCE_REV, t["origin"], "threat source")]
            if "attackPatterns" in t:
                mechanisms = []
                for pattern_ref in t["attackPatterns"]:
                    pattern = patterns[pattern_ref]
                    mechanism = {"capec_id": pattern["capecId"]}
                    if pattern_ref not in untitled:
                        mechanism["capec_title"] = pattern["name"]
                    mechanisms.append(mechanism)
                threat["attack_mechanisms"] = verbatim(t, "attack-mechanisms", mechanisms)
            if "weaknesses" in t:
                titles = {int(m.group(1)): m.group(2) for m in (CWE_TITLE.match(e.get("comment", ""))
                          for e in t.get("externalReferences", []) if e["url"].startswith(CWE_URL.format("")[:-5])) if m}
                weaknesses = []
                for w in t["weaknesses"]:
                    weakness = {"cwe_id": w["cweId"]}
                    put(weakness, "cwe_title", titles.get(w["cweId"]))
                    weaknesses.append(weakness)
                threat["weaknesses"] = verbatim(t, "weaknesses", weaknesses)
            tm["threats"].append(threat)

    if "controls" in bom:
        tm["controls"] = []
        for c in bom["controls"]:
            control_ref = c["bom-ref"]
            control = {"symbolic_name": unref("control", control_ref), "title": c["name"], "description": c["description"],
                       "threats": verbatim(c, "threats", mitigated.get(control_ref, []))}
            for target in c.get("appliesTo", []):
                if target.startswith("trust-boundary:"):
                    control["trust_boundary"] = unboundary_ref(target)
            control["status"] = lookup(CONTROL_STATUS_REV, c["status"], "control status")
            control["priority"] = prop_of(c, "priority")
            tm["controls"].append(control)

    if "risks" in bom:
        tm["risks"] = []
        for r in bom["risks"].get("risks", []):
            inherent = r["inherentRisk"]
            tm["risks"].append({
                "symbolic_name": unref("risk", r["bom-ref"]), "title": r["name"], "description": r["statement"],
                "threats": verbatim(r, "threats", [unref("threat", t) for t in r.get("relatedThreats", [])]),
                "likelihood": lookup(LIKELIHOOD_REV, inherent["likelihood"]["level"], "likelihood"),
                "impact": lookup(IMPACT_REV, inherent["impact"]["level"], "impact"),
                "impact_description": inherent["impact"]["description"],
                "score": int(inherent["score"]["score"]),
                "level": prop_of(r, "risk-level") or RISK_LEVEL_EXACT[inherent["score"]["level"]],
            })

    extensions = {}
    for key, value in bom.items():
        if key.startswith("ext:"):
            domain, path = key[len("ext:"):].split(":", 1)
            extensions[domain + path] = value
    for value in props_of(bom, "extension"):
        entry = json.loads(value)
        extensions[entry["key"]] = entry["value"]
    if extensions or prop_of(bom, "extensions") is not None:
        tm["extensions"] = extensions
    return tm


# --- CLI --------------------------------------------------------------------

def first_difference(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {a!r} != {b!r}"
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                return f"{path}.{key}: {'missing after round trip' if key in a else 'added by round trip'}"
            diff = first_difference(a[key], b[key], f"{path}.{key}")
            if diff:
                return diff
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            diff = first_difference(x, y, f"{path}[{i}]")
            if diff:
                return diff
        return None
    return None if a == b else f"{path}: {a!r} != {b!r}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("to-cyclonedx", "to-native"):
        p = sub.add_parser(name)
        p.add_argument("input")
        p.add_argument("-o", "--output")
    sub.add_parser("check").add_argument("inputs", nargs="+")
    args = parser.parse_args()

    if args.command == "check":
        failed = 0
        for path in args.inputs:
            with open(path) as f:
                original = json.load(f)
            try:
                diff = first_difference(original, to_native(json.loads(json.dumps(to_cyclonedx(original)))))
            except ConversionError as e:
                diff = f"conversion error: {e}"
            print(f"{'LOSSY' if diff else 'ok   '} {path}" + (f"\n      {diff}" if diff else ""))
            failed += bool(diff)
        sys.exit(1 if failed else 0)

    with open(args.input) as f:
        document = json.load(f)
    result = to_cyclonedx(document) if args.command == "to-cyclonedx" else to_native(document)
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
