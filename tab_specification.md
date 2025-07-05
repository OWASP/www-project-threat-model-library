---
title: Specification
layout:  null
tab: true
order: 1
tags: example-tag
---

# **OWASP Threat Model Library Schema Specification**

This specification explains each major element defined in the OWASP Threat Model Library JSON Schema. It is designed to help understand the purpose and relationships of various schema components.

## **Document Metadata**

### **`version`**

A structured version number (e.g., "1.0") representing the current version of the threat model. Helps track evolution of the model over time.

### **`$schema`**

Specifies the Threat Model Library schema, and its specific version, the threat model document conforms to. For example:

`“$schema”: “https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.0/threat-model.schema.json”`

## **System Description**

The following top-level properties describe the system being threat-modeled.

### **`scope`**

Defines the boundary and criticality of what is being modeled. This is foundational to any threat modeling exercise, as it determines what is included/excluded \- “scoping the work” is a common terminology used in threat modelling or other security domains like pentesting.

* `title`: Name of the system being modeled.  
* `description`: Describes what’s in scope and what’s out of scope. This is distinct from the description of the system’s purpose and behavior, which goes in the *top-level* `description` property, separate from `scope`.  
* `business_criticality`: Indicates how important the system is to business operations. This helps prioritize risk mitigation.  
* `data_sensitivity`: Flags if the system handles sensitive data types (e.g., credentials, PII). Critical for compliance and privacy.  
* `exposure`: `internal` or `external` access. Externally facing systems are at higher risk.  
* `tier`: Prioritization tier used to guide depth of modeling, risk exposure and review frequency.  
  * `mission_critical:`   
    * business criticality maximal \+ external  
    * business critical maximal \+ stores sensitive data  
    * business criticality high \+ stores sensitive data \+ external  
  * `business_critical`  
    * business criticality maximal and no sensitive data, internal  
    * business criticality high \+ external but no sensitive data  
    * business criticality high \+ sensitive data \+ internal  
    * business criticality moderate but sensitive data \+ external  
  * `important`  
    * business criticality moderate and below \+ sensitive data  
    * business criticality moderate \+ external, no sensitive data  
  * `non_critical`  
    * business criticality moderate and below \+ internal and no sensitive data  
    * business criticality low and minimal, no sensitive data, can be external

### `description`

Describes the system’s purpose and behavior and any other business context not otherwise captured.

## **Architecture Modeling**

### **`trust_zones`**

Logical areas with uniform trust assumptions (e.g., public internet, internal VPC, secure enclave). Used to define boundaries of exposure and control. Each `component` is assigned to a `trust zone`. 

### **`trust_boundaries`**

Interfaces where data crosses from one trust zone to another. These are high-risk areas in any architecture:

* Controls (e.g., authentication, access control) must be explicitly modeled here.  
* To exist they must be defined with controls such as encryption, authentication, token management, session security …  
* If a trust boundary is not defined then that is a threat modelling finding \- the root cause of potential threats\!


### **`actors`**

These are commonly known as entities. Human or machine entities that interact with the system. Key to identifying external threats and misuse scenarios.

### **`components`**

Building blocks of the system (e.g., APIs, backend services). Central to threat modeling since most threats target specific components.

### **`data_stores`**

Where data is stored or persisted. Important for identifying risks like unauthorized access, data corruption, and backups.

### **`data_sets`**

Logical groupings of data. Mapping datasets to their stores helps clarify data flow, exposure, and sensitivity.

### **`data_flows`**

Represents communication between components, actors, and data stores. Data flows are key to STRIDE-based threat modeling and attack path analysis.

### **`diagrams`**

Enables visual system modeling using PlantUML, Mermaid, or similar. Essential for collaboration and reviewing architecture.

## **Security Modeling**

### **`assumptions`**

Things you take as true about your system (e.g., "TLS terminates at the load balancer"). Helps clarify model boundaries and gaps. 

* `description`: An arbitrary statement about the system.  
* `topics`: A list of topics on which the assumption makes a statement. These topics will be of a standardized taxonomy and must not be arbitrarily chosen. As of right now, no topics have been standardized, so this property must not be specified.  
* `validity`: Whether the assumption is `unconfirmed` (proposed/assumed by a stakeholder), `confirmed` (definitely true), or `rejected` (proposed but known to be false).

### **`threat_personas`**

Adversary profiles that inform how and why threats might be realized. Useful for risk assessment and simulating realistic attacker behavior.

Aids in justifying and validating threats. Supports structured persona-based modeling and possible support for integration with threat detection tools in the future.

### **`threats`**

Individual threat events. Each threat references its persona, attack vector (CAPEC), and weakness (CWE). They are the core unit of security concern in the model.

### **`controls`**

Implementations of mitigations tied to specific threats. Helps ensure your model leads to actionable recommendations.

**Effectiveness of controls:** Added as a property (e.g., minimal to maximal scale) to assess relative control strength.

Distinguished from mitigations which is the process of implementing countermeasures. A mitigation is the **effect** or **strategy** of reducing risk, rather than the specific tool or mechanism. 

We chose the term "controls" over alternatives like "mitigations" or "countermeasures" because:

* controls is more aligned with risk and governance frameworks such as ISO 27001, NIST, CIS, and SOC2  
* it reflects the language used in security audits, risk treatment plans, and governance reporting  
* it's broader and implementation-agnostic, a control can be preventive, detective, or corrective \- not just a technical fix  
* "mitigation" often implies reduction in risk, but not full prevention  
* "countermeasure" is more military/technical and less used in enterprise security governance  
* it enables clearer mapping between threat models and control libraries, using controls makes it easier to link threat model outputs to control catalogs like NIST 800-53, OWASP ASVS, or CIS Controls

In short, “control” unifies threat modeling with risk governance and enterprise security frameworks — making threat models more actionable and aligned with business processes.

### **`risks`**

Risk is a function of the likelihood of a threat event / scenario’s occurrence and potential adverse impact should the event occur. A risk should be present only if a vulnerability or weakness are present that could lead to a threat event. Ties the threat model to risk management practices and governance. Enables prioritization.

Even though risks are influenced by org-specific factors (impact context, likelihood drivers), the schema retains this optional element to support linkage with enterprise risk registers.

####  **`summary`**
To formulate a risk summary consider how a threat with an exploitable weakness or vulnerability leads to a risk event and certain impact. 

#### **`likelihood`**

Likelihood is a factor of risk. To estimate the likelihood consider the applicability of the threat persona to the business context, threat source, threat scenario, existing vulnerabilities or pre-existing conditions.

####  **`impact`**

 Impact is a factor of Risk. Key considerations for impact are:

 - **Operational Impact**: How the threat affects business processes.
- **Financial Impact**: The potential monetary loss.
- **Reputation Impact**: Public perception and long-term trust.
- **Regulatory/Legal Impact**: Fines, penalties, or legal consequences.

####  **`level`**

- **Methodology**: `Likelihood x Impact`
- **Output**:
  - **Score**: Numerical
  - **Descriptive**: Text label (e.g., Low, Medium, High)

####  **`score`**

The cross product of impact and likelihood yields the risk score, a scale from 1 to 25:

#### 5x5 Risk Level Matrix

The cross product of impact and likelihood yields the risk score (1–25). Color-coded with emojis to reflect severity bands:

#### 5x5 Risk Level Matrix

The cross product of impact and likelihood yields the risk score (1–25). The matrix below is color-coded with square emojis to reflect severity bands:

| **Likelihood \ Impact** | **1 (Negligible)** | **2 (Minor)** | **3 (Moderate)** | **4 (Major)** | **5 (Severe)** |
|--------------------------|--------------------|----------------|------------------|----------------|----------------|
| **1 (Rare)**             | 🟩 1 _(Very Low)_   | 🟩 2 _(Very Low)_ | 🟨 3 _(Low)_     | 🟨 4 _(Low)_     | 🟧 5 _(Medium)_     |
| **2 (Unlikely)**         | 🟩 2 _(Very Low)_   | 🟨 4 _(Low)_     | 🟧 6 _(Medium)_   | 🟧 8 _(Medium)_   | 🟥 10 _(High)_       |
| **3 (Possible)**         | 🟨 3 _(Low)_        | 🟧 6 _(Medium)_   | 🟧 9 _(Medium)_   | 🟥 12 _(High)_    | 🟪 15 _(Very High)_  |
| **4 (Likely)**           | 🟨 4 _(Low)_        | 🟧 8 _(Medium)_   | 🟥 12 _(High)_    | 🟪 16 _(Very High)_| 🔴 20 _(Critical)_    |
| **5 (Almost Certain)**   | 🟧 5 _(Medium)_     | 🟥 10 _(High)_    | 🟪 15 _(Very High)_| 🔴 20 _(Critical)_ | 🔴 25 _(Critical)_    |



Based on the numerical value of the risk score, we define the following risk levels:

| **Risk Score Range** | **Risk Level** |
|----------------------|----------------|
| 🟩 1–2                  | Very Low       |
| 🟨3–4                  | Low            |
| 🟧 5–9                  | Medium         |
| 🟥 10–12                | High           |
| 🟪13–16                | Very High      |
| 🔴20–25                | Critical       |

#### Likelihood and impact assesment guidance


| **Value** | **Likelihood**     | **Definition**                                                                 |
|-----------|--------------------|--------------------------------------------------------------------------------|
| 1         | Rare               | Very unlikely to occur; may happen only in exceptional circumstances, such as once in 10+ years. |
| 2         | Unlikely           | Could occur but not expected; has happened once in 5–10 years.                |
| 3         | Possible           | Might occur under some circumstances; happens every 2–5 years.               |
| 4         | Likely             | Expected to occur in some situations; happens at least once a year.           |
| 5         | Almost Certain     | Expected to occur regularly; happens multiple times a year or more frequently.|

#### Impact Severity Definitions

| **Value** | **Impact Severity**     | **Operational Impact**                                                | **Financial Impact**             | **Reputation Impact**                                            | **Regulatory/Legal Impact**                                     |
|-----------|-------------------------|------------------------------------------------------------------------|----------------------------------|------------------------------------------------------------------|------------------------------------------------------------------|
| 1         | Insignificant           | Minimal disruption, no noticeable effect on business operations.       | <0.1% of annual revenue.         | No damage to reputation.                                         | No legal or regulatory implications.                            |
| 2         | Minor                   | Some minor disruption, but recoverable with little effort.             | 0.1% to 0.5% of annual revenue.  | Small, localized damage to reputation, quickly recoverable.      | Minor compliance issues, no fines or legal action.              |
| 3         | Moderate                | Noticeable operational impact, moderate recovery efforts required.     | 0.5% to 1% of annual revenue.    | Moderate reputation damage; some negative press, recoverable.    | Possible fines or legal action; warning from regulators.        |
| 4         | Major                   | Significant operational disruption; requires substantial resources.    | 1% to 5% of annual revenue.      | Significant damage to reputation; major loss of customer trust.  | Substantial legal issues; fines and regulatory penalties.       |
| 5         | Severe     | Critical operational impact; operations cease or major losses.         | >5% of annual revenue.           | Severe reputation damage; long-term loss of market position.     | Major legal action; large fines; potential shutdown.            |


## **Extensions**

### **`extensions`**

Allows custom fields while enforcing namespace uniqueness. Enables organizations to capture additional data relevant to their threat modeling workflows. For example:

```json
{
  ...
  "extensions": {
    "example.com/owasp-threat-model-foobar-extension": {
      // Whatever schema is needed, whereas the schema should be clearly
      // documented at https://example.com/owasp-threat-model-foobar-extension.
      ...
    },
    "example.net/other-extension": {
      // Analogously.
      ...
    }
  }
}
```

This schema enables traceable, evidence-backed, and enterprise-ready threat modeling for modern systems. It is optimized for structured outputs, tool integration, and supports formal risk analysis through linkage of threats, risks, and mitigations.

For implementation guidance or examples, refer to [https://github.com/OWASP/www-project-threat-model-library](https://github.com/OWASP/www-project-threat-model-library).

