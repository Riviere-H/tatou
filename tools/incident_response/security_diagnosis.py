
"""
Tatou Security Incident Diagnosis Tool
Provides quick security assessment and incident investigation capabilities.
"""
import os
import json
import subprocess
import requests
from datetime import datetime, timedelta
import argparse

class SecurityDiagnosis:
    def __init__(self):
        self.results = {}
        
    def check_service_status(self):
        """Check if all services are running"""
        print(" Checking service status...")
        try:
            result = subprocess.run(
                ["sudo", "docker", "compose", "ps", "--format", "json"],
                capture_output=True, text=True, timeout=30
            )
            
            services = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            service_data = json.loads(line)
                            service.append({
                                "name": service_data.get("Service", ""),
                                "status": service_data.get("State", ""),
                                "health": service_data.get("Health", ""),
                                "ports": service_data.get("Ports", "")
                            })
                        except json.JSONDecodeError:
                            continue

            if not services:
                services =  self.parse_service_status_text()
                
            self.results['service'] = services
            print(f" Found {len(services)} services")
            return services
    
        except Exception as e:
            print(f"Service check failed: {e}")
            return self.parse_service_status_text()


    def parse_service_status_text(self):
        try:
            result = subprocess.run(
                ["sudo", "docker", "compose", "ps"],
                capture_output=True, text=True, timeout=30
            )

            services = []
            lines = result.stdout.strip().split('\n')

            for line in lines[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        service_name = parts[0]
                        status_index = None

                        for i, part in enumerate(parts):
                            if part.startswith("Up") or part.startswith("Exit"):
                                status_index = i
                                break

                        if status_index is not None:
                            status = "".join(parts[status_index:status_index+3])

                            services.append({
                                "name": service_name,
                                "status": status,
                                "health": "",
                                "ports": ""
                            })

            return services

        except Exception as e:
            print(f" Text parsing also failed: {e}")
            return []

    def check_service_status_simple(self):
        print("Checking service status...")
        try:
            result = subprocess.run(
                ["sudo", "docker", "compose", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=30
            )

            services = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        services.append({
                            "name": parts[0],
                            "status": parts[1],
                            "health": "",
                            "ports": ""
                        })

            self.results['services'] = services
            print (f" Found {len(services)} services")
            return services

        except Exception as e:
            print (f" Simple service check failed: {e}")
            return []
    
    def check_recent_security_events(self, hours=24):
        """Check recent security events from logs"""
        print(f" Checking security events from last {hours} hours...")
        try:
            # Get recent security events from container logs
            result = subprocess.run([
                "sudo", "docker", "compose", "logs", "--tail=1000", "server"
            ], capture_output=True, text=True, timeout=30)
            
            security_events = []
            for line in result.stdout.split('\n'):
                if any(keyword in line.lower() for keyword in
                      ['security', 'error', 'failed', 'unauthorized', 'attack']):
                    security_events.append(line.strip())
            
            self.results['recent_security_events'] = security_events
            print(f" Found {len(security_events)} security-related log entries")
            return security_events
        except Exception as e:
            print(f" Security events check failed: {e}")
            return []

    def check_prometheus_alerts(self):
        """Check current Prometheus alerts"""
        print(" Checking Prometheus alerts...")
        try:
            response = requests.get("http://localhost:9090/api/v1/alerts", timeout=10)
            alerts = response.json().get('data', {}).get('alerts', [])
            
            active_alerts = [alert for alert in alerts
                           if alert.get('state') in ['firing', 'pending']]
            
            self.results['active_alerts'] = active_alerts
            print(f" Found {len(active_alerts)} active alerts")
            return active_alerts
        except Exception as e:
            print(f" Prometheus alerts check failed: {e}")
            return []
    
    def check_flag_status(self):
        """Check flag file status and access patterns"""
        print(" Checking flag file status...")
        flag_checks = {}
        
        try:
            # Check if flag files exist and get their status
            flags_to_check = [
                ("/app/flag", "Container flag")
            ]
            
            for flag_path, description in flags_to_check:
                try:
                    result = subprocess.run([
                        "sudo", "docker", "compose", "exec", "server",
                        "bash", "-c", f"ls -la {flag_path} 2>/dev/null || echo 'NOT_FOUND'"
                    ], capture_output=True, text=True, timeout=10)
                    
                    flag_checks[description] = {
                        "exists": "NOT_FOUND" not in result.stdout and "No such file" not in result.stdout,
                        "output": result.stdout.strip()
                    }
                except Exception as e:
                    flag_checks[description] = {"exists": False, "output": "Check failed: {e}"}
            
            self.results['flag_status'] = flag_checks
            print(" Flag status check completed")
            return flag_checks
        except Exception as e:
            print(f" Flag status check failed: {e}")
            return {}

    
    def check_network_connections(self):
        """Check suspicious network connections"""
        print(" Checking network connections...")
        try:
            result = subprocess.run([
                "sudo", "docker", "compose", "exec", "server",
                "netstat", "-tunlp"
            ], capture_output=True, text=True, timeout=10)
            
            connections = []
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'LISTEN' in line:
                    connections.append(line.strip())
            
            self.results['network_connections'] = connections
            print(f" Found {len(connections)} network connections")
            return connections
        except Exception as e:
            print(f" Network connections check failed: {e}")
            return []
    
    def generate_report(self):
        """Generate comprehensive security diagnosis report"""
        print("\n" + "="*50)
        print("SECURITY DIAGNOSIS REPORT")
        print("="*50)
        
        # Service Status
        print("\n📊 SERVICE STATUS:")
        for service in self.results.get('services', []):
            status_icon = "✅" if "up" in service['status'].lower() else "❌"
            print(f"  {status_icon} {service['name']}: {service['status']}")
        
        # Active Alerts
        print("\n🚨 ACTIVE ALERTS:")
        alerts = self.results.get('active_alerts', [])
        if alerts:
            for alert in alerts:
                print(f"  ⚠️ {alert.get('labels', {}).get('alertname', 'Unknown')}: {alert.get('state')}")
        else:
            print(" No active alerts")
        
        # Flag Status
        print("\n🚩 FLAG STATUS:")
        for desc, status in self.results.get('flag_status', {}).items():
            status_icon = "✅" if status.get('exists') else "❌"
            print(f"  {status_icon} {desc}: {'Exists' if status['exists'] else 'Missing'}")
        
        # Security Events Summary
        events = self.results.get('recent_security_events', [])
        print(f"\n RECENT SECURITY EVENTS: {len(events)} events found")
        
        # Save detailed report
        report_file = f"logs/security_diagnosis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs('logs', exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n Detailed report saved to: {report_file}")
        return report_file

def main():
    parser = argparse.ArgumentParser(description='Tatou Security Diagnosis Tool')
    parser.add_argument('--quick', action='store_true', help='Run quick assessment only')
    parser.add_argument('--simple', action='store_true', help='Use simple service check')
    
    args = parser.parse_args()
    
    print(" Starting Tatou Security Diagnosis...")
    diagnosis = SecurityDiagnosis()
    
    # Run checks
    if args.simple:
        diagnosis.check_service_status_simple()
    else:
        diagnosis.check_service_status()

    diagnosis.check_prometheus_alerts()
    diagnosis.check_flag_status()
    
    if not args.quick:
        diagnosis.check_recent_security_events()
        diagnosis.check_network_connections()
    
    # Generate report
    report_file = diagnosis.generate_report()
    
    print(f"\n Diagnosis completed. Check {report_file} for details.")

if __name__ == "__main__":
    main()
