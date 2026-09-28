# Deyda Security Tools

A collection of practical security assessment, detection and incident response tools developed and maintained by **Deyda Consulting GmbH**.

The repository contains scripts and utilities created for real-world security assessments, vulnerability response and infrastructure security operations.

## Purpose

The goal of this repository is to provide practical tools that help administrators, consultants and security professionals to:

- assess systems for known security issues
- identify potential Indicators of Compromise (IoCs)
- validate security configurations
- perform post-update and post-mitigation checks
- support vulnerability assessment and incident response
- automate repetitive security checks

The tools are primarily developed from practical experience with enterprise infrastructure and security incidents.

## Tools

### NetScaler

Security assessment and incident response tooling for NetScaler ADC and NetScaler Gateway.

Examples include:

- IoC detection
- CVE-specific checks
- firmware and mitigation validation
- configuration security checks
- filesystem and log analysis
- persistence detection
- post-compromise assessment

Additional tools will be added over time.

## Repository Structure

Each tool is stored in its own directory and includes documentation covering:

- purpose
- requirements
- usage
- available parameters
- interpretation of results
- known limitations

Always review the documentation and source code before executing a script in a production environment.

## Important

These tools are intended to **assist security assessments**.

A successful or clean result does **not** guarantee that a system has not been compromised.

Indicators of Compromise, attack techniques and vulnerabilities evolve continuously. Results should therefore always be evaluated together with vendor security advisories, system logs, network telemetry and other available forensic evidence.

For suspected compromises, a proper incident response and forensic investigation should be performed.

## Contributions

Issues, technical feedback and contributions are welcome.

If you discover a false positive, false negative or additional detection method, please open an issue or submit a pull request.

When reporting security-sensitive information, avoid publishing confidential customer data, credentials, Indicators of Compromise related to an active incident, or other sensitive information.

## Disclaimer

The scripts and information provided in this repository are intended for security assessment, defensive security and incident response purposes.

Use them only on systems you own or are explicitly authorized to assess.

The tools are provided without warranty. Always review scripts before executing them and test them in an appropriate environment before using them on production systems.

## License

Licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for details.

## About Deyda Consulting

**Deyda Consulting GmbH**

Specialized consulting for Citrix, NetScaler, Microsoft and enterprise infrastructure security.

https://www.deyda-consulting.de

Technical articles, security research and infrastructure findings:

https://www.deyda.net
