# DevSecOps Pipeline Showcase

This repository serves as a reference implementation for integrating security practices into your development pipeline using GitHub Actions. It demonstrates how to implement a comprehensive DevSecOps approach in a modern web application stack.

## Architecture Overview

The repository contains a complete application stack:

- Frontend: React-based web application
- Backend: Python FastAPI service
- Infrastructure: Terraform configurations for AWS deployment

## Security Pipeline Features

Our security pipeline implements industry best practices for continuous security testing:

- Static Application Security Testing (SAST)
  - Python code analysis using Bandit
  - Infrastructure code scanning using tfsec
- Software Composition Analysis (SCA)
  - Dependency scanning with Dependabot
- Container Security
  - Base image vulnerability assessment
- Infrastructure as Code (IaC) Security
  - Checkov analysis with calibrated outputs
- Security Testing
  - Front-end security testing with OWASP ZAP

All security findings are exported in SARIF format and integrated with GitHub Security dashboard.

## Repository Structure

```
├── .github/
│   └── workflows/         # GitHub Actions pipeline definitions
├── web-app/               # React web application
├── python-app/            # Python FastAPI service
├── infra/                # Terraform configurations
└── tests/                # Test suites including security tests
```

## Pipeline Configuration

The security pipeline is defined in `.github/workflows/security-scan.yml`

**Note**: This is a demonstration repository intended to showcase DevSecOps practices. While the security controls are real, the application code is simplified for educational purposes.

**Note**: This repository requires PAT called GH_PAT with repository and security access
