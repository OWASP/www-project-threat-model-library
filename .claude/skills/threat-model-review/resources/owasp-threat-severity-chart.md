---
title: Threat Severity Chart
layout: col-sidebar
tags: threatmodeling
---

<!--
  Mirrored from https://github.com/OWASP/www-project-threat-modeling
  (resources/threat-severity-chart.md) on 2026-08-19 for offline/reliable use
  by the threat-model-review skill. This is a DIFFERENT OWASP project from
  the one this repo belongs to (www-project-threat-model-library) — it
  classifies the severity of an individual threat (Critical/Important/
  Moderate/Low), not a business risk (likelihood x impact, this repo's own
  `risks.level`). If upstream has changed since the mirror date, prefer the
  live version.
-->

> **Status:** Reference Chart

## Threat Severity Classification Framework

Adapted from the Microsoft SDL Bug Bar. This framework is used to triage and classify threats against our systems, services, and devices. Severity is assigned based on the nature of the threat, the context in which it can be triggered, and the degree of user interaction or authentication required.

When a lower-severity threat class can be combined with by-design behaviour to achieve a higher-severity outcome, the threat is rated at the higher class.

---

## General Principles

| Term | Definition |
|------|------------|
| Unauthenticated / anonymous | The attacker has no valid credentials or established session |
| Authenticated | The attacker holds valid credentials for the target system |
| User interaction | A legitimate user must take an action (click, open, visit) for the threat to succeed |
| Extensive user interaction | User must navigate deliberately, e.g. manually typing a URL or clicking through multiple warning dialogs. Clicking an email link does not count as extensive |
| Persistent | The effect survives a restart of the application, service, or system |
| Temporary | The effect is reversed by restarting the application, service, or system |
| High-value asset | Domain controllers, certificate authorities, identity providers, HSMs, core CI/CD infrastructure |
| OTA | Over-the-air: Wi-Fi, Bluetooth, or other wireless communication channels |
| PII | Personally Identifiable Information: any data that can identify an individual, either directly (e.g. name, national ID, biometrics) or indirectly when combined with other data (e.g. location history, device identifiers, behavioural patterns) |
| Confidential / Restricted data | Data formally classified as confidential or restricted by the organisation's data classification policy, regardless of whether it constitutes PII |

---

## Server / Cloud and Client Threats

The **Context** column indicates which environment(s) the row applies to. Where both contexts share the same category and severity level, examples are split inline. For **Auth Required** and **User Interaction**, values are noted per context where they diverge.

- **All** — applies to both Server / Cloud and Client
- **Server / Cloud** — on-premises servers, virtualised infrastructure, and cloud-hosted services (IaaS, PaaS, SaaS, multi-tenant APIs)
- **Client** — browsers, desktop applications, mobile/store apps, and processes running in a local interactive user session

| Level | Category | Context | Auth Required | User Interaction | Security Impact | Definition | Examples |
|-------|----------|---------|--------------|-----------------|-----------------|------------|----------|
| **Critical (4)** | Unauthorised Access / Privilege Escalation | All | No | None | Code Execution / Full Compromise | Remote unauthenticated RCE or full compromise without meaningful user interaction. | **Server / Cloud:** Memory corruption in anonymously callable code; SQLi to OS exec; SSRF to IAM creds; container/VM escape to host or hypervisor; tenant escape impacting others. **Client:** Drive-by exploit on default browser; memory corruption via file preview or message; guest VM to hypervisor host; network-wormable condition. |
| **Critical (4)** | Data Exfiltration / Info Disclosure | Server / Cloud | No | None | Confidentiality Loss | Cross-tenant or cross-VM data read with no authentication or interaction. | Read another tenant's or VM's data unauthenticated. |
| **Critical (4)** | Tampering / Integrity | Server / Cloud | No | None | Integrity Loss | Unauthenticated, persistent modification of state or filesystem in default configs. | Arbitrary writes to FS; modify IaC/DNS/routing with persistent effect in default setup. |
| **Important (3)** | Denial of Service | All | No | None (Server) · Required (Client) | Availability Loss | Sustained, amplified, or system-corrupting unavailability in common/default scenarios. | **Server / Cloud:** Anonymous persistent DoS on core roles; quota exhaustion; amplified DoS causing >1m outage; authenticated persistent DoS on high-value assets; tenant/guest-induced host DoS. **Client:** System-corruption DoS requiring full reinstallation; drive-by DoS (unauthenticated, default exposure, no user interaction, no audit trail — e.g. drive-by Bluetooth crash). |
| **Important (3)** | Unauthorised Access / Privilege Escalation | All | Yes (Server) · No (Client) | None (Server) · Extensive (Client) | Privilege Escalation / Code Execution | Significant privilege gain in common scenarios. | **Server / Cloud:** Misconfigured IAM/managed identity enabling elevation; authenticated non-admin can exec code or write to FS. **Client:** RCE with extensive user interaction; exploitable Write AVs / kernel Read AVs in remotely callable code; sandbox escape; use of sensitive capabilities without user knowledge; local low-privilege user to admin or SYSTEM. |
| **Important (3)** | Data Exfiltration / Info Disclosure | All | Yes (Server) · No (Client) | None | Confidentiality Loss | User or process reads data beyond intended scope in common scenarios. | **Server / Cloud:** PII or confidential/restricted data disclosure; kernel memory read by user-mode; other tenants' data; secrets in env vars; open cloud storage. **Client:** Unauthorised FS read; user-mode reading kernel memory; memory layout leak enabling DEP/ASLR bypass for subsequent RCE; guest VM reads host or sibling VM memory; PII or confidential/restricted data (email addresses, phone numbers, DOB, ...). |
| **Important (3)** | Spoofing / Identity Abuse | All | No | None | Identity Compromise | Convincing impersonation or auth manipulation enabling chosen-identity access in common scenarios. | **Server / Cloud:** Chosen user/computer/cloud identity impersonation; OIDC/SAML assertion manipulation; coerced auth relay without interaction. **Client:** UI visually identical to trust-decision surface in default scenario; anonymous coercion of endpoint to authenticate to attacker-controlled machine without user interaction. |
| **Important (3)** | Tampering / Integrity | All | No | None | Integrity Loss | Persistent, high-impact modification in common/default cases. | **Server / Cloud:** Modify high-value asset data, infra config, or trust-decision data; proxy/CDN cache poisoning in common setup. **Client:** Persistent modification of user or trust-decision data; browser cache poisoning; arbitrary writes outside app container without user interaction. |
| **Important (3)** | Social Engineering / Phishing | All | No | Required (victim) | Credential / Identity Loss | Auth flows hijacked server-side, or phishing surface indistinguishable from legitimate UI, in default scenario. | **Server / Cloud:** OAuth redirect URI manipulation in server-to-server flows. **Client:** Spoofed OAuth consent screen or fake MFA prompt in default browsing scenario. |
| **Important (3)** | Lateral Movement | Server / Cloud | Yes (workload identity) | None | Access Expansion | Compromised workload identity expands access beyond the initial boundary. | Service account/managed identity/instance role leveraged to reach other internal services without new credentials. |
| **Important (3)** | Supply Chain / Dependency | Server / Cloud | No | None | Code Execution / Integrity Loss | Shared build/deploy/runtime component compromise reaching production in default configs. | Poisoned base image; tampered internal package; pipeline step runs attacker code with deploy rights. |
| **Important (3)** | Security Feature Bypass | Client | No | None | Control Bypass | Disabling or bypassing endpoint protection, secure boot, biometric authentication, or full-disk encryption without user knowledge or consent. | — |
| **Moderate (2)** | Denial of Service | All | No | None (Server) · Required (Client) | Availability Loss (recoverable) | Scoped or recoverable unavailability; mitigations or restarts restore service. | **Server / Cloud:** Session/connection exhaustion; non-memory-safety DoS; amplified query saturating CPU for minutes; non-default degradation. **Client:** Persistent DoS requiring a cold reboot or system crash, triggered by opening a document, browsing to a page, or launching an application. |
| **Moderate (2)** | Data Exfiltration / Info Disclosure | All | No | None | Confidentiality Loss (limited) | Limited/specific data read or trackable data exposure aiding later attacks. | **Server / Cloud:** Targeted reads from known but non-exposed locations; file/version existence; unauthenticated resource enumeration. **Client:** Read from known but non-exposed locations (file existence, version numbers); PII, confidential/restricted data, or location data over unencrypted connection; trackable identifiers (email, GPS, device ID) sent to third-party server. |
| **Moderate (2)** | Spoofing / Identity Abuse | All | No | Required | Identity Compromise (limited) | Impersonation or credential relay feasible only in narrow or user-assisted scenarios. | **Server / Cloud:** Random entity masquerade; misconfigured trust used for cross-service auth; user-assisted credential relay. **Client:** Spoofed UI in specific non-default scenario (e.g. spoofed file extension in attachment); authenticated or user-triggered credential relay to attacker-controlled machine. |
| **Moderate (2)** | Tampering / Integrity | Server / Cloud | Yes | None | Integrity Loss (scoped) | Persistent change only in specific/non-default cases; common cases reset on restart. | Scoped persistent modification; temporary change in default scenarios that clears on restart. |
| **Moderate (2)** | Lateral Movement | Server / Cloud | Yes | None | Access Expansion (limited) | Cross-boundary movement achievable only with misconfiguration or non-default setup. | Traverse network/account boundaries using existing identities in non-default/misconfigured scenarios. |
| **Moderate (2)** | Lateral Movement | Client | Yes (stolen session) | None | Access Expansion | Client-side credentials leveraged to reach internal services without additional exploitation. | Session tokens or cached credentials used to authenticate to internal services from the compromised client. |
| **Moderate (2)** | Supply Chain / Dependency | Server / Cloud | Yes | None | Code Execution (conditional) | Third-party weakness exploitable only with specific configs or an authenticated trigger. | Outdated/vulnerable dependency needs special setup or authentication to exploit. |
| **Moderate (2)** | Supply Chain / Dependency | Client | No | Required (install/use) | Code Execution (sandboxed) | Client-side dependency executes code within the app sandbox in a default configuration. | Compromised npm package, browser extension, or update mechanism. |
| **Low (1)** | Data Exfiltration / Info Disclosure | All | No | None | Confidentiality Loss (negligible) | Non-sensitive, incidental, or untargeted disclosure without exploitable secrets or broad impact. | **Server / Cloud:** Verbose errors, benign memory strings, or stack traces without secrets. **Client:** Untargeted leak of non-sensitive heap memory. |
| **Low (1)** | Tampering / Integrity | All | No | None | Integrity Loss (temporary) | Scoped, temporary change with no lasting security effect. | **Server / Cloud:** Minor config/data tweak in specific scenarios; no persistence or material impact. **Client:** Temporary data modification that does not persist after restart. |
| **Low (1)** | Denial of Service | Client | No | Required | Availability Loss (temporary) | Temporary DoS requiring only an application restart. | Crash on opening a specific file type. |
| **Low (1)** | Spoofing / Identity Abuse | Client | No | Required | Identity Compromise (partial) | Spoofed UI is one step in a multi-stage attack requiring additional exploitation. | Requires further exploitation before having any security impact. |

---

## Hardware Threats

**Key terms:**

- **OTA** — Wi-Fi, Bluetooth, or other supported wireless channels
- **External device** — any device connected via an external port, including PCIe/Thunderbolt, displays, and batteries (excludes CPUs, RAM, power supplies)
- **Expected user interaction** — actions required to use a legitimate version of the attacking device type (plugging in, pressing a button, using a paired app)
- **Unexpected user interaction** — any action beyond expected interaction

| Severity | Threat Category | Auth Required | User Interaction | Security Impact | Conditions & Examples |
|----------|-----------------|--------------|-----------------|-----------------|-----------------------|
| **Critical (4)** | Unauthorised Access / Privilege Escalation | No | Expected only | Code Execution / Full Compromise | OTA drive-by attack requiring only expected user interaction; attacker needs only to be within wireless range. Example: malicious Bluetooth peripheral achieves RCE on the host with no more interaction than the user having Bluetooth enabled. |
| **Important (3)** | Unauthorised Access / Privilege Escalation | No | Unexpected · Expected | Privilege Escalation / Code Execution | OTA attack requiring unexpected user interaction. External device connected (with or without any interaction) executes code at a higher privilege level than the triggering user. External device with expected interaction executes code in the user's own context. |
| **Important (3)** | Denial of Service | No | Expected only | Availability Loss | OTA drive-by DoS with expected user interaction only; attacker within wireless range. |
| **Important (3)** | Data Exfiltration / Info Disclosure | No | Any | Confidentiality Loss | External device (any interaction) leaks data back to the attacker. OTA attack (any interaction) leaks data from a more privileged context to the attacker. |
| **Moderate (2)** | Unauthorised Access / Privilege Escalation | No | Unexpected | Code Execution (same context) | External device with unexpected user interaction executes code in the same context as the interacting user (no privilege gain). |
| **Moderate (2)** | Denial of Service | No | Unexpected | Availability Loss | OTA attack requiring unexpected user interaction. |
| **Low / None (1)** | Denial of Service | No | Required | Availability Loss (minor) | External device connection causing DoS that does not meet the Important or Moderate definitions above. |

---

## Severity Summary Reference

| Severity | Colour | General Definition |
|----------|--------|--------------------|
| **(!) Critical (4)** | Red | Wormable, unauthenticated, or unavoidable full compromise. No user interaction required, or interaction is trivial (e.g. previewing a file). |
| **(x) Important (3)** | Orange/Amber | Significant compromise possible in common scenarios, typically requiring authentication, user interaction, or mitigations that reduce but do not eliminate risk. |
| **(*) Moderate (2)** | Blue | Limited-scope or non-default scenarios; mitigations exist; effect is recoverable or constrained. |
| **(i) Low (1)** | Green | Minimal security impact; typically untargeted, non-sensitive, or fully temporary. |
