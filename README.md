# Dev Sec Ops Automated Scanning
Security automation jobs built with GitHub Actions using Security automation pipelines built with GitHub Actions using industry-standard open-source tooling for dependency analysis, SBOM generation, SAST, and Infrastructure-as-Code security validation. Soon to add more features.

## Tooling

### OSV Scanner
Dependency vulnerability scanner maintained by Google for detecting known vulnerabilities in open-source packages and lockfiles.

- Repository: :[contentReference[oaicite:0]{index=0}](https://github.com/google/osv-scanner)

### CycloneDX CLI
CLI utility for validating, converting, merging, and analyzing CycloneDX Software Bill of Materials (SBOMs).

- Repository:[ :contentReference[oaicite:1]{index=1}](https://github.com/CycloneDX/cyclonedx-cli)

### Bearer
Static Application Security Testing (SAST) and sensitive data analysis platform focused on identifying security and privacy risks within source code.

- Repository:[ :contentReference[oaicite:2]{index=2}](https://github.com/Bearer/bearer/security)

### Checkov
Infrastructure-as-Code security scanner supporting Terraform, Kubernetes, Dockerfiles, GitHub Actions, CloudFormation, Helm, and additional cloud-native technologies.

- Repository:[ :contentReference[oaicite:3]{index=3}](https://github.com/bridgecrewio/checkov)

# Workflows

| Workflow | Description |
|---|---|
| `osv-scanner.yml` | Performs dependency vulnerability analysis and exports SARIF + CycloneDX reports |
| `cyclonedx-sbom.yml` | Generates, validates, and converts CycloneDX SBOM artifacts |
| `bearer-sast.yml` | Executes SAST and sensitive data analysis against application source code |
| `checkov-iac.yml` | Scans Infrastructure-as-Code and CI/CD configurations for security misconfigurations |

---

# Pipeline Capabilities

- GitHub Actions CI/CD security automation
- SARIF integration with GitHub Advanced Security
- Automated SBOM generation and validation
- Dependency vulnerability detection
- Static application security testing
- Infrastructure-as-Code policy enforcement
- Artifact retention for auditability and review
- Scheduled and event-driven security scanning

# Outputs

Generated pipeline artifacts include:

- SARIF security findings
- CycloneDX SBOMs
- Vulnerability assessment reports
- Infrastructure misconfiguration findings
- Source code security analysis reports

# Security Coverage

This repository includes scanning coverage for:

- Open-source dependencies
- CI/CD workflows
- Terraform configurations
- Kubernetes manifests
- Dockerfiles
- Application source code
- Sensitive data exposure risks
- Software supply chain artifacts

# Usage

```bash
git clone https://github.com/yourusername/devsecops-security-pipelines.git
cd devsecops-security-pipelines
