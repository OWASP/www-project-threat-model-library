# OWASP Threat Model Library 📚

**🎯 Our Mission**

To enable secure software architectures by democratising threat modeling through open-source, community engagement and AI advancements with clean, vetted and reliable data.

Welcome to the first, open-sourced, structured, peer-reviewed threat modeling dataset. By generating this open-source curated dataset of real-world threat models, we aim to:

1. Promote and contribute to the standardization of threat modelling
2. Contribute to the knowledge exchange between peers by reviewing every model.
3. Improve the security of open-source applications by having them openly threat modeled. Death to security via obscurity!
4. Create a dataset to fine-tune existing pre-trained LLMs to achieve more reliable threat modeling results

## News

- Project will be presented at the OWASP Global AppSec in Barcelona on 29th of May 2025, along with the release of the schema!

- [v1.0.0](https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.0/threat-model.schema.json) of the schema is out! 

## Road Map

1. **Start Receiving Contributions!**
    - See the schema, uploaded examples and start threat modelling!

3. **Community Engagement:**
    - Workshops and [hackathons](https://airtable.com/appwu5c5wt1zJXhIQ/pagnNjTTHWSMQJIer/form) will be organized to promote collaboration and encourage community involvement.

4. **Threat Modeling for Popular Open Source Software:**
    - Initiatives will be launched to model the security threats of widely used open-source software.

## FAQs

1. **How do I contribute?**

   - Start by threat modeling! The JSON schema is available, and there are example threat models too. Use these examples to create your threat model and submit a pull request (PR) on the repository. Detailed contribution guidelines will be provided once the schema is finalized.
   - To understand the schema better head over to the schema [specification tab on our page](https://owasp.org/www-project-threat-model-library/)!
   - Contribute by donating - head over to the OWASP Projects Page, click [donate](https://owasp.org/donate/?reponame=owasp.github.io) and contributions can go directly to us if you donate more than $1000!
   - Register interest for a hackathon [here](https://airtable.com/appwu5c5wt1zJXhIQ/pagnNjTTHWSMQJIer/form). 
   - You can propose schema improvements by creating an issue with the label `schema-proposals` and we will discuss it on the TM-BOM workgroup. Before the TM-BOM comes out we will try to minimise any schema changes. 
   - Get involved in the discussions on the **Discussions** tab.

2. **What is the CycloneDX TM-BOM?**

   CycloneDX TM-BOM (Threat Model Bill of Materials) is an industry-standard specification that provides a way to describe threat models. The official release is pending! 
   Once TM-BOM is released, there will be another version released of the Threat Model Library Schema to ensure semantic compatibility.

3. **What tools can I use for threat modeling?**

   There are several tools available for threat modeling, both open-source and commercial. Some popular options include:

   - **OWASP Threat Dragon** (open-source)
   - **OWASP pytm** (open-source)
   - **Microsoft Threat Modeling Tool** (free, proprietary)

   You can use any tool you're comfortable with as long as the output can be converted into the JSON format once the schema is published.

4. **How will threat models be reviewed and validated?**

   Threat models submitted to the repository will be reviewed by the maintainers and the community. The review process will ensure that the model adheres to the schema, follows best practices, and provides meaningful insights. Reviewers may request adjustments or additional details before merging.

5. **What happens after I submit a threat model?**

   After submission, the maintainers and community will review the model. If it meets the standards, it will be merged into the library. We encourage contributors to continuously update and refine threat models as new information or threats emerge.

6. **Will there be support or training for beginners in threat modeling?**

   Yes, we plan to offer training resources, workshops, and tutorials for those who are new to threat modeling. These resources will help you understand the key concepts, tools, and best practices in threat modeling.

7. **How do I report issues or suggest improvements to the project?**

   If you encounter any issues or have suggestions for improvement, you can open an issue in the project’s GitHub repository. Be sure to provide as much detail as possible, and if applicable, a proposed solution or workaround.

8. **How can I validate a threat model JSON file against the schema?**

   We recommend the [`check-jsonschema`](https://github.com/python-jsonschema/check-jsonschema) or [`jsonschema`](https://github.com/python-jsonschema/jsonschema) Python CLI tools. For example:

   ```shell
   $ check-jsonschema --schemafile threat-model.schema.json threat-models/husky-ai-threat-model.json 
   ```

## Thank You Notes

Thank you to our sponsors from [DevArmor](devarmor.com)!

Contributions will be used for organising hackathons and community engagement. 
Register interest for a hackathon [here](https://airtable.com/appwu5c5wt1zJXhIQ/pagnNjTTHWSMQJIer/form). 

Thank you to the [CycloneDX](https://owasp.org/www-project-cyclonedx/) TM-BOM workgroup - including:

- [Steve Springett](mailto:steve.springett@owasp.org)
- [Izar Tarandach](mailto:izar.tarandach@gmail.com)

## Contact Us

- [Petra Vukmirovic](mailto:petra.vukmirovic@owasp.org)
- [Julian Mehnle](mailto:julian@mehnle.net)
- [OWASP #project-threat-model-library Slack channel](https://owasp.slack.com/archives/C08UNEQTPUY)
