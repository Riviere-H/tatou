
# Tatou System Inventory

## Document Information
- **Created**: 03.10
- **Version**: 2.0

## 1. Application Components

### 1.1 Core Services

| Asset ID |      Component       | Version |       Description       |        Location        |  Status | Criticality |
|----------|----------------------|---------|-------------------------|------------------------|---------|-------------|
| APP-001  | Flask Application    | 3.0.3   | Main web application    | `server/src/server.py` | Active  | High        |
| APP-002  | Gunicorn WSGI Server | 21.2.0  | Production WSGI server  | Container runtime      | Active  | High        |
| DB-001   | MariaDB Database     | 11.4    | Primary data storage    | `db` container         | Active  | Critical    |
| DB-002   | phpMyAdmin           | 5.2     | Database administration | `phpmyadmin` container | Active  | Medium      |
| MON-001  | Prometheus           | latest  | Metrics collection      | Planned                | Planned | Medium      |
| MON-002  | Grafana              | latest  | Monitoring dashboard    | Planned                | Planned | Medium      |

### 1.2 Watermarking Modules

| Asset ID |           Module             | Version |            Description            | Criticality | Risk Level |
|----------|------------------------------|---------|-----------------------------------|-------------|------------|
| WM-001   | Phantom Annotation Watermark |   1.0   | Group 21 custom watermarking      |     High    |   Medium   |
| WM-002   | AddAfterEOF                  |   1.0   | Basic EOF watermarking            |    Medium   |    Low     |
| WM-003   | UnsafeBashBridgeAppendEOF    |   1.0   | Bash-based watermarking (secured) |     Low     |    Low     |

### 1.3 Authentication & Security

| Asset ID |     Component    |  Version |         Description         | Status | Criticality |
|----------|------------------|----------|-----------------------------|--------|-------------|
| AUTH-001 | JWT Token System | Custom   | Bearer token authentication | Active |     High    |
| AUTH-002 | RMAP Protocol    | 1.0.0    | GPG-based authentication    | Active |     High    |
| AUTH-003 | Password Hashing | Werkzeug | Argon2/Bcrypt hashing       | Active |     High    |
| SEC-001  | Rate Limiting    | Custom   | In-memory rate limiter      | Active |    Medium   |


## 2. Data Assets

### 2.1 Database Schema

**Tables:**
- `Users` - User accounts and credentials (Critical)
- `Documents` - Original PDF metadata (High) 
- `Versions` - Watermarked document versions (High)

### 2.2 File Storage

| Asset ID |   Storage Type   |               Location                 |         Contents          |  Access Control  | Criticality |
|----------|------------------|----------------------------------------|---------------------------|------------------|-------------|
| FS-001   | Original PDFs    | `/app/storage/files/{user}`            | User-uploaded documents   | User-specific    |     High    |
| FS-002   | Watermarked PDFs | `/app/storage/files/{user}/watermarks` | Watermarked versions      | Public via links |    Medium   |
| FS-003   | RMAP Watermarks  | `/app/storage/rmap_watermarks`         | RMAP-generated watermarks | RMAP clients     |    Medium   |
| FS-004   | Plugin Storage   | `/app/storage/files/plugins`           | Custom watermark plugins  | Admin users      |     Low     |

### 2.3 Security Assets

| Asset ID |      Asset Type      |        Location       | Sensitivity |      Protection       | Criticality |
|----------|----------------------|-----------------------|-------------|-----------------------|-------------|
| SEC-002  | GPG Keys             | `/app/keys/`          |    High     | File permissions      |   Critical  |
| SEC-003  | JWT Secret           | Environment variables |    High     | Environment isolation |   Critical  |
| SEC-004  | Database Credentials | Environment variables |    High     | Environment isolation |   Critical  |
| SEC-005  | Flag Files           | Multiple locations    |  Critical   | File permissions      |   Critical  |


## 3. Infrastructure Components

### 3.1 Container Architecture

| Asset ID |   Service  |         Image          | Ports | Criticality |
|----------|------------|------------------------|-------|-------------|
| INF-001  | server     | Python 3.12-slim       |  5000 |    High     |
| INF-002  | db         | mariadb:11.4           |  3306 |   Critical  |
| INF-003  | phpmyadmin | phpmyadmin:5.2         |  8080 |   Medium    |
| INF-004  | prometheus | prom/prometheus:latest |  9090 |   Medium    |
| INF-005  | grafana    | grafana/grafana:latest |  3000 |   Medium    |

### 3.2 Network Configuration

| Asset ID |   Service  | Internal Port | External Port  |   Access   | Criticality |
|----------|------------|---------------|----------------|------------|-------------|
| NET-001  | Flask App  |      5000     |      5000      | Public     |     High    |
| NET-002  | MariaDB    |      3306     | 127.0.0.1:3306 | Local only |   Critical  |
| NET-003  | phpMyAdmin |       80      | 127.0.0.1:8080 | Local only |    Medium   |
| NET-004  | Prometheus |      9090     |      9090      | Planned    |    Medium   |
| NET-005  | Grafana    |      3000     |      3000      | Planned    |    Medium   |

## 4. Dependencies

### 4.1 Python Dependencies

**Critical Dependencies:**
- Flask==3.0.3 (APP-001)
- PyMuPDF>=1.21.1 (WM modules)
- rmap @ git+https://github.com/nharrand/RMAP-Server.git@v1.0.0 (AUTH-002)

**High Dependencies:**
- gunicorn==21.2.0 (APP-002)
- PyMySQL==1.1.2 (DB-001)
- SQLAlchemy==2.0.43 (DB-001)

**Medium Dependencies:**
- prometheus-client==0.20.0 (MON-001)
- python-json-logger==2.0.7 (logging)

### 4.2 System Dependencies

| Asset ID |   Dependency   | Version |          Purpose           | Criticality |
|----------|----------------|---------|----------------------------|-------------|
| SYS-001  | Python         |  3.12   | Runtime environment        |  Critical   |
| SYS-002  | Docker         |  20+    | Containerization           |    High     |
| SYS-003  | Docker Compose |  2.0+   | Multi-container management |    High     |
| SYS-004  | Git            |  2.0+   | Version control            |   Medium    |

## 5. Asset Classification Summary

### 5.1 Criticality Distribution

| Criticality Level | Count | Percentage |
|-------------------|-------|------------|
|     Critical      |   8   |    23%     |
|       High        |  11   |    32%     |
|      Medium       |  14   |    40%     |
|       Low         |   2   |     5%     |

### 5.2 Risk Assessment

**High Risk Assets:**
- Database (DB-001) - Contains sensitive user data
- GPG Keys (SEC-002) - RMAP authentication backbone
- JWT Secrets (SEC-003) - Application authentication
- Flag Files (SEC-005) - Course evaluation criteria

**Medium Risk Assets:**
- Application components (APP-001, APP-002)
- Watermarking modules (WM-001)
- File storage (FS-001, FS-002)


## 6. Change History

| Version |  Date  |               Changes                  |   Author    |
|---------|--------|----------------------------------------|-------------|
|   1.0   | 03.10. | Initial inventory document             |      J      |
|   2.0   | 05.10. | Added asset IDs and criticality labels |      J      |
