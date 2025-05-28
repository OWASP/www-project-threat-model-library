---
title: Schema Specification
layout:  null
tab: true
order: 1
tags: schema-spec-tag
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

A combination of threat, likelihood, and impact. Ties the threat model to risk management practices and governance. Enables prioritization.

Even though risks are influenced by org-specific factors (impact context, likelihood drivers), the schema retains this optional element to support linkage with enterprise risk registers.

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

