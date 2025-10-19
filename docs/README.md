# Tatou Operational Security Specialization Documentation

## Document Structure

- `inventory.md` - System component and dependency inventory
- `threat_model.md` - Threat modeling and risk assessment
- `logging-guide.md` -  Structured logging and audit configuration
- `metrics.md` - Monitoring metrics and Prometheus integration
- `incident_response.md` - Incident response procedures and drills


## Project Overview

Tatou is a PDF watermarking platform originally designed for secure document handling.
This specialization (Specialization D) focuses on building *operational security capabilities* around the existing system, including threat modeling, auditable logging, monitoring and security incident response 


## Specialization Objectives

1. **Threat Modeling** - Identify and assess system security threats
2. **Structured Logging** - Implement auditable security operation logs
3. **Monitoring & Alerting** - Establish security event detection and response capabilities
4. **Incident Response** - Develop and test security incident handling procedures


## References

### Threat Modeling Methodologies

- **STRIDE Framework** - Microsoft Threat Modeling Methodology
- **OWASP Threat Modeling** - Open Web Application Security Project
- **ENISA Threat Taxonomy** - European Union Agency for Cybersecurity

### Security Operations Standards

- **NIST SP 800-61** - Computer Security Incident Handling Guide
- **ISO 27035** - Information Security Incident Management
- **CIS Critical Security Controls** - Center for Internet Security

### Monitoring and Logging Standards

- **Prometheus Monitoring System** - CNCF Graduated Project
- **ELK Stack** - Elasticsearch, Logstash, Kibana Logging Platform
- **OpenTelemetry** - CNCF Observability Framework


## Environment Setup

### Basic Environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   # Or .venv\Scripts\activate  # Windows
   pip install -e ".[dev]"
   ```

### Copy environment template and configure:
   ```bash
   cp env.sample .env
   # Edit .env file with real values

### Main Dependencies
Main project dependencies are defined in `pyproject.toml`.

### Operational Security Dependencies 

For the operational security specialization, install additional dependencies:

```bash
# Install all optional dependencies (including development tools)
pip install -r tools/requirements-optional.txt

# Or install only core monitoring dependencies
pip install prometheus-client==0.20.0 python-json-logger==2.0.7
```

## Start services:
   ```bash
   docker compose up --build -d
   ```
