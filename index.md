---

layout: col-sidebar
title: OWASP Threat Model Library
tags: example-tag
level: 2
type: code
pitch: Welcome to the first, open-sourced, structured, peer-reviewed threat modeling dataset

---

Welcome to the first, open-sourced, structured, peer-reviewed threat modeling dataset. By generating this open-source curated dataset of real-world threat models, we aim to:

1. Promote and contribute to the standardization of threat modelling
2. Contribute to the knowledge exchange between peers by reviewing every model.
3. Improve the security of open-source applications by having them openly threat modeled. Death to security via obscurity!
4. Create a dataset to fine-tune existing pre-trained LLMs to achieve more reliable threat modeling results

## News

Project will be presented at the OWASP Global AppSec in Barcelona, along with the release of the schema!


## Road Map


1. **Define the Schema:**
    - Establish a standard format for all threat models to be added to the project.
    - The schema will ensure that threat models are both machine-readable and human-readable.
    - **ETA:** To be confirmed, but expected by the end of April 2025 (likely sooner). The timeline is subject to ongoing work for alignment with CycloneDx TM-BOM.

2. **Start Receiving Contributions!**
    - We will begin accepting contributions once the schema is defined.

3. **Community Engagement:**
    - Workshops will be organized to promote collaboration and encourage community involvement.

4. **Threat Modeling for Popular Open Source Software:**
    - Initiatives will be launched to model the security threats of widely used open-source software.

---

## FAQs

1. **How do I contribute?**

   Start by threat modeling! Once the JSON schema is available, we'll also provide example models. Use these examples to create your threat model and submit a pull request (PR) on the repository. Detailed contribution guidelines will be provided once the schema is finalized.

2. **I want to start now, without waiting for the schema. Can you provide any guidance on the core elements of the schema?**

   The schema will include (but is not limited to) the following key elements:

   - **Scope of the Threat Model**: Define the boundaries and context of the threat model.
   - **Actors and Permissions**: Identify the actors and their associated permissions.
   - **Diagram-as-Code**: Represent the system and its components visually using code such as PlantUML or Mermaid.
   - **Components**: List and describe the components involved in the system.
   - **Data Storage & Datasets**: Detail the storage systems and the datasets they handle.
   - **Data Flows**: Describe the data flows, including sources and destinations.
   - **Threats**: Identify the potential threats.
   - **Threat Personas**: Define the different personas associated with the threats.
   - **Prioritized Controls**: List the mitigations, prioritized according to their importance.
   - **Risks**: Include the risk level, likelihood, and impact of each identified threat.

3. **What is the CycloneDx TM-BOM?**

   CycloneDx TM-BOM (Threat Model Bill of Materials) is an industry-standard specification that provides a way to describe threat models. The official release is pending!

4. **What tools can I use for threat modeling?**

   There are several tools available for threat modeling, both open-source and commercial. Some popular options include:

   - **OWASP Threat Dragon** (open-source)
   - **OWASP pytm** (open-source)
   - **Microsoft Threat Modeling Tool** (free, proprietary)

   You can use any tool you're comfortable with as long as the output can be converted into the JSON format once the schema is published.

5. **How will threat models be reviewed and validated?**

   Threat models submitted to the repository will be reviewed by the maintainers and the community. The review process will ensure that the model adheres to the schema, follows best practices, and provides meaningful insights. Reviewers may request adjustments or additional details before merging.

6. **What happens after I submit a threat model?**

   After submission, the maintainers and community will review the model. If it meets the standards, it will be merged into the project. We encourage contributors to continuously update and refine threat models as new information or threats emerge.

7. **Will there be support or training for beginners in threat modeling?**

   Yes, we plan to offer training resources, workshops, and tutorials for those who are new to threat modeling. These resources will help you understand the key concepts, tools, and best practices in threat modeling.

8. **How do I report issues or suggest improvements to the project?**

   If you encounter any issues or have suggestions for improvement, you can open an issue in the project’s GitHub repository. Be sure to provide as much detail as possible, and if applicable, a proposed solution or workaround.



