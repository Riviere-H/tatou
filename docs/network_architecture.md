
# Tatou Network Architecture

## 1. Network Overview

### 1.1 Architecture Diagram

```

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   External      │    │   Docker         │    │   University    │
│   Users         │────│   Network        │────│   VM Network    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
│                        │                        │
│                        │                        │
Port 5000 (HTTP)        Internal Bridges        Isolated Network

```

### 1.2 Service Connectivity

| Asset ID |  Service   | Internal Network | External Exposure | Protocol | Criticality |
|----------|------------|------------------|-------------------|----------|-------------|
| NET-001  | Flask App  | `tatou_default`  | `0.0.0.0:5000`    |   HTTP   |     High    |
| NET-002  | MariaDB    | `tatou_default`  | `127.0.0.1:3306`  |   TCP    |   Critical  |
| NET-003  | phpMyAdmin | `tatou_default`  | `127.0.0.1:8080`  |   HTTP   |    Medium   |
| NET-004  | Prometheus | `tatou_default`  | `0.0.0.0:9090`    |   HTTP   |    Medium   |
| NET-005  | Grafana    | `tatou_default`  | `0.0.0.0:3000`    |   HTTP   |    Medium   |


## 2. Network Segmentation

### 2.1 Subnet and IP Allocation

|      Network       |     Subnet     |            Purpose             | Default Gateway | Criticality |
|--------------------|----------------|--------------------------------|-----------------|-------------|
| tatou_default      | 172.18.0.0/16  | Default internal Docker bridge | 172.18.0.1      |    High     |
| University Network | 10.11.202.0/23 | External access network        | 10.11.203.255   |   Medium    |
| docker0            | 172.17.0.0/16  | Default Docker bridge          | 172.17.0.1      |     Low     |

### 2.2 Container IP Assignment

|  Service   |   Container Name   | IP Address |   Gateway  | Status |
|------------|--------------------|------------|------------|--------|
| server     | tatou-server-1     | 172.18.0.3 | 172.18.0.1 | Active |
| db         | tatou-db-1         | 172.18.0.2 | 172.18.0.1 | Active |
| phpmyadmin | tatou-phpmyadmin-1 | 172.18.0.4 | 172.18.0.1 | Active |
| prometheus | tatou-prometheus-1 | 172.18.0.5 | 172.18.0.1 | Active |
| grafana    | tatou-grafana-1    | 172.18.0.6 | 172.18.0.1 | Active |


## 3. Security Zones and Trust Boundaries

### 3.1 Security Zones

**External Zone (Untrusted):**
- University network users (10.11.202.0/23) accessing ports 5000, 9090, 3000
- Other groups in university network
- **Criticality**: Low trust, High monitoring

**DMZ Zone (Semi-trusted):**
- Flask application container (NET-001)
- Prometheus metrics server (NET-004)
- Grafana dashboard (NET-005)
- External-facing services
- **Criticality**: Medium trust, Medium monitoring

**Internal Zone (Trusted):**
- Database container (NET-002)
- Administrative interfaces (NET-003)
- Internal metrics endpoints
- **Criticality**: High trust, Low monitoring


### 3.2 Network Access Control Matrix

|                Source               | Destination | Protocol | Port | Action |         Purpose           |
|-------------------------------------|-------------|----------|------|--------|---------------------------|
| University Network (10.11.202.0/23) |  NET-001    |    TCP   | 5000 | ALLOW  | Application access        |
| University Network (10.11.202.0/23) |  NET-004    |    TCP   | 9090 | ALLOW  | Prometheus metrics        |
| University Network (10.11.202.0/23) |  NET-005    |    TCP   | 3000 | ALLOW  | Grafana dashboard         |
| NET-001                             |  NET-002    |    TCP   | 3306 | ALLOW  | Database access           |
| NET-001                             |  NET-003    |    TCP   |  80  | ALLOW  | Admin interface           |
| Any                                 |  NET-002    |    TCP   | 3306 |  DENY  | Database isolation        |
| Any                                 |  NET-003    |    TCP   |  80  |  DENY  | Admin interface isolation |
| Any                                 |  NET-004    |    TCP   | 9090 | ALLOW  | Prometheus (public)       |
| Any                                 |  NET-005    |    TCP   | 3000 | ALLOW  | Grafana (public)          |


## 4. Network Security Controls

### 4.1 Implemented Controls

**Firewall Rules:**
- Database only accessible from localhost and application container
- Administrative interfaces restricted to localhost
- University network isolation for external services

**Application-Level Controls:**
- Input validation and sanitization
- Rate limiting on authentication endpoints
- JWT token validation with client fingerprinting
- CORS configuration for API endpoints

**Container Security:**
- Non-root user execution
- Limited container capabilities
- Resource constraints (CPU, memory)
- Read-only root filesystem where possible

### 4.2 Network Policy (Planned)

**Inter-container Communication:**
- Restrict inter-container communication except via defined application ports
- Enforce `--icc=false` in Docker daemon for inter-container isolation
- Define container-level firewall via `iptables` or `ufw-docker`

**Network Monitoring:**
- Implement network traffic analysis
- Detect unusual port activity
- DDoS protection mechanisms
- Intrusion detection system integration

### 4.3 Traffic Control Strategies

**Rate Limiting:**
- API endpoints: 100 requests/minute per IP
- Authentication endpoints: 5 attempts/minute per IP
- File uploads: 10MB maximum size

**Quality of Service:**
- Priority for authentication traffic
- Bandwidth limits for file downloads
- Connection timeouts for long-running operations


## 5. Incident Response Network Considerations

### 5.1 Isolation Procedures

1. **Service Isolation**: Stop affected containers immediately
2. **Network Isolation**: Block suspicious IP addresses at firewall level
3. **Database Isolation**: Restrict database access to essential services only
4. **Forensic Access**: Preserve network logs and container state

### 5.2 Recovery Procedures

1. **Service Restoration**: Restart containers from clean, verified images
2. **Network Restoration**: Verify and restore firewall rules
3. **Access Control**: Reset all credentials, tokens, and API keys
4. **Enhanced Monitoring**: Implement temporary enhanced network monitoring


## 6. Network Performance and Monitoring

### 6.1 Performance Baselines

|          Metric        |      Normal Range      |  Alert Threshold  |  Criticality |
|------------------------|------------------------|-------------------|--------------|
| Response Time          |         < 500ms        |     > 2000ms      |     High     |
| Concurrent Connections |         < 100          |     > 500         |    Medium    |
| Bandwidth Usage        |         < 10 Mbps      |     > 50 Mbps     |    Medium    |
| Error Rate             |         < 1%           |     > 5%          |     High     |

### 6.2 Monitoring Endpoints

|     Endpoint     |       Purpose       |  Access  | Criticality |
|------------------|---------------------|----------|-------------|
| `/healthz`       | Application health  | Public   |    High     |
| `/metrics`       | Prometheus metrics  | Internal |   Medium    |
| Database metrics | Performance metrics | Internal |  Critical   |


## 7. Incident Response Network Procedures

### 7.1 Network Forensics Data Sources

**Log Sources for Network Incidents:**
- Docker container logs (`docker compose logs`)
- Application access logs (Flask request logging)
- Database connection logs (MariaDB general query log)
- System network connections (`netstat`, `ss`)
- Firewall logs (iptables/ufw if enabled)

**Network Evidence Preservation:**
1. **Immediate Actions**: 
   - Capture current network connections
   - Save routing tables and interface configurations
   - Document active port listeners

2. **Forensic Collection**:
   - Export Docker network configuration
   - Capture packet captures (if feasible)
   - Preserve firewall rule state

### 7.2 Network Isolation Commands

```bash
# Emergency network isolation examples
# Block an attacking IP
sudo iptables -A INPUT -s MALICIOUS_IP -j DROP

# Isolate a compromised container
docker network disconnect tatou_default COMPROMISED_CONTAINER

# Emergency service shutdown
docker compose stop server  # If server compromised
docker compose stop db      # If database compromised


## 8 Network Monitoring Enhancement Plan

### 8.1 Short-term Monitoring (Phase 3)

· Application-level metrics (response times, error rates)
· Basic network connectivity checks
· Container resource usage monitoring

### 8.2 Medium-term Monitoring (Phase 4)

· Network traffic analysis between containers
· DDoS detection and mitigation
· Suspicious port activity alerts

### 8.3 Long-term Monitoring (Future)

· Full packet capture for forensic analysis
· Advanced intrusion detection system
· Network behavior analytics

  
## 9. Change History

| Version |   Date   |                      Changes                          |  Author |
|---------|----------|-------------------------------------------------------|---------|
|   1.0   |   04.10  | Initial network architecture                          |    J    |
|   2.0   |   06.10  | Added asset IDs, network policies, and security zones |    J    |
