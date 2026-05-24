# DevSecOps Security Scanning Pipelines

Security automation pipelines built with GitHub Actions using open-source tooling for dependency analysis, SBOM generation, SAST, secrets scanning, container security, and Infrastructure-as-Code validation.

## Tools Used

### OSV Scanner
Dependency vulnerability scanner maintained by Google for detecting known vulnerabilities in open-source packages and lockfiles.

- Repository: https://github.com/google/osv-scanner

### CycloneDX CLI
CLI utility for validating, converting, merging, and analyzing CycloneDX Software Bill of Materials (SBOMs).

- Repository: https://github.com/CycloneDX/cyclonedx-cli

### Checkov
Infrastructure-as-Code security scanner supporting Terraform, Kubernetes, Dockerfiles, GitHub Actions, CloudFormation, Helm, and cloud-native configuration files.

- Repository: https://github.com/bridgecrewio/checkov

### Trivy
Cloud-native security scanner for vulnerabilities, misconfigurations, secrets, containers, filesystems, Git repositories, and SBOMs.

- Repository: https://github.com/aquasecurity/trivy
- GitHub Action: https://github.com/aquasecurity/trivy-action

### Semgrep
Static analysis engine for finding insecure coding patterns, dangerous API usage, injection risks, hardcoded secrets, and custom policy violations.

- Repository: https://github.com/semgrep/semgrep

---

## Included Workflows

| Workflow | Purpose |
|---|---|
| `osv-scanner.yml` | Dependency vulnerability scanning with SARIF and CycloneDX outputs |
| `cyclonedx-sbom.yml` | SBOM generation, validation, and conversion |
| `checkov-iac.yml` | Infrastructure-as-Code and CI/CD security scanning |
| `trivy-security.yml` | Filesystem vulnerability, misconfiguration, and secret scanning |
| `semgrep-sast.yml` | Static code analysis for insecure coding patterns |
| `security-consolidated-report.yml` | Downloads latest scanner artifacts and builds one multi-sheet Excel report |

---

## Security Coverage

This project demonstrates automated security coverage across:

- Open-source dependency vulnerabilities
- Software supply chain visibility
- CycloneDX SBOM generation and validation
- Static application security testing
- Infrastructure-as-Code misconfigurations
- Container and filesystem vulnerabilities
- Secret exposure risks
- CI/CD workflow security
- Cloud-native configuration issues

---

## Outputs

Generated pipeline artifacts include:

- SARIF security findings
- CycloneDX SBOM files
- Dependency vulnerability reports
- SAST reports
- IaC misconfiguration findings
- Trivy filesystem scan reports
- Semgrep static analysis reports
- Consolidated Excel report with a dedicated sheet per scanner and a Risk Review summary sheet

---

## Usage

Place the workflow files inside:

```text
.github/workflows/
```

Then push to `main`, open a pull request, or manually run the workflows from the GitHub Actions tab.

To generate a single consolidated workbook from all scanner artifacts, run:

`Security Consolidated Excel Report`

The workflow publishes these artifacts:

- `security-consolidated-report` (Excel workbook: `reports/security-consolidated.xlsx`)
- `security-consolidated-metadata` (artifact source and missing-source summary)

Security findings are available in:

- GitHub Actions workflow runs
- GitHub Security / Code Scanning
- Uploaded workflow artifacts

---

## Project Goal

This repository demonstrates hands-on DevSecOps implementation through reusable CI/CD security automation. The goal is to show practical security engineering experience across dependency scanning, SBOM handling, SAST, IaC validation, secret scanning, and cloud-native security workflows.
