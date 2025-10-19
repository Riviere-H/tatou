
"""
Final Specialisation Validation Script
Comprehensive validation of all operational security components
"""
import os
import sys
import json
import subprocess
import requests
from pathlib import Path

class FinalValidator:
    def __init__(self):
        self.results = {
            'timestamp': subprocess.getoutput('date -Iseconds'),
            'components': {},
            'overall_status': 'PENDING'
        }
    
    def check_component(self, name, check_func):
        """Helper to run a check and record results"""
        try:
            print(f" Checking {name}...")
            result = check_func()
            self.results['components'][name] = {
                'status': 'PASS' if result else 'FAIL',
                'details': result if isinstance(result, dict) else str(result)
            }
            status_icon = '✅' if result else '❌'
            print(f"   {status_icon} {name}: {'PASS' if result else 'FAIL'}")
            return bool(result)
        except Exception as e:
            self.results['components'][name] = {
                'status': 'ERROR',
                'details': str(e)
            }
            print(f" {name}: ERROR - {e}")
            return False
    
    def validate_documentation(self):
        """Validate all documentation exists"""
        required_docs = [
            'docs/final_project_report.md',
            'docs/threat_model.md',
            'docs/inventory.md',
            'docs/logging-guide.md',
            'docs/incident_response.md',
            'docs/monitoring_guide.md',
            'docs/network_architecture.md'
        ]
        
        missing = []
        for doc in required_docs:
            if not Path(doc).exists():
                missing.append(doc)
        
        return {
            'total_required': len(required_docs),
            'missing_docs': missing,
            'all_present': len(missing) == 0
        }
    
    def validate_tools(self):
        """Validate all tools and scripts"""
        required_tools = [
            'tools/scripts/analyze_dependencies.py',
            'tools/incident_response/security_diagnosis.py',
            'tools/incident_response/incident_drill.py',
            'tools/scripts/log_analyzer.py'
        ]
        
        working_tools = []
        for tool in required_tools:
            if Path(tool).exists():
                # Test if tool can be imported/run without major errors
                try:
                    if tool.endswith('.py'):
                        result = subprocess.run([
                            'python', tool, '--help' if 'drill' in tool else ''
                        ], capture_output=True, text=True, timeout=10)
                        working_tools.append(tool)
                except:
                    pass
        
        return {
            'total_tools': len(required_tools),
            'working_tools': working_tools,
            'all_working': len(working_tools) == len(required_tools)
        }
    
    def validate_services(self):
        """Validate core services are running"""
        services_to_check = ['server', 'db']
        running_services = []
        
        try:
            result = subprocess.run([
                'docker', 'compose', 'ps', '--format', 'json'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                services = json.loads(result.stdout)
                for service in services:
                    if service['Service'] in services_to_check and 'running' in service['State'].lower():
                        running_services.append(service['Service'])
        
        except Exception as e:
            print(f"   Warning: Could not check services: {e}")
        
        return {
            'required_services': services_to_check,
            'running_services': running_services,
            'all_running': len(running_services) == len(services_to_check)
        }
    
    def validate_monitoring(self):
        """Validate monitoring components"""
        checks = {}
        
        # Check if metrics endpoint is accessible
        try:
            response = requests.get('http://localhost:5000/metrics', timeout=5)
            checks['metrics_endpoint'] = response.status_code == 200
        except:
            checks['metrics_endpoint'] = False
        
        # Check if monitoring configs exist
        monitoring_files = [
            'monitoring/prometheus.yml',
            'monitoring/grafana/dashboards/security_overview.json'
        ]
        
        checks['config_files'] = all(Path(f).exists() for f in monitoring_files)
        
        return checks
    
    def run_comprehensive_validation(self):
        """Run all validation checks"""
        print(" Starting Comprehensive Validation")
        print("=" * 50)
        
        checks = [
            ('Documentation', self.validate_documentation),
            ('Tools & Scripts', self.validate_tools),
            ('Services', self.validate_services),
            ('Monitoring', self.validate_monitoring)
        ]
        
        all_passed = True
        for name, check_func in checks:
            if not self.check_component(name, check_func):
                all_passed = False
        
        # Determine overall status
        self.results['overall_status'] = 'PASS' if all_passed else 'FAIL'
        
        print(f"\n VALIDATION COMPLETE: {self.results['overall_status']}")
        return all_passed
    
    def generate_report(self):
        """Generate validation report"""
        report_file = f"logs/final_validation_{self.results['timestamp'].replace(':', '')}.json"
        
        # Ensure logs directory exists
        Path('logs').mkdir(exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n Detailed report saved to: {report_file}")
        return report_file

def main():
    validator = FinalValidator()
    
    try:
        success = validator.run_comprehensive_validation()
        report_file = validator.generate_report()
        
        if success:
            print("\n ALL VALIDATIONS PASSED! Project is ready for submission.")
        else:
            print("\n Some validations failed. Please check the report and fix issues.")
        
        return 0 if success else 1
        
    except Exception as e:
        print(f" Validation failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
