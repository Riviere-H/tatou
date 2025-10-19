
import requests
import json
import sys

def check_prometheus_targets():
    try:
        response = requests.get("http://localhost:9090/api/v1/targets")
        data = response.json()
        
        tatou_target = None
        for target in data['data']['activeTargets']:
            if target['labels']['job'] == 'tatou-app':
                tatou_target = target
                break
        
        if tatou_target and tatou_target['health'] == 'up':
            print("✓ Prometheus target: HEALTHY")
            return True
        else:
            print("✗ Prometheus target: UNHEALTHY")
            return False
            
    except Exception as e:
        print(f"✗ Prometheus check failed: {e}")
        return False

def check_metrics_availability():
    try:
        metrics_to_check = [
            "security_events_total",
            "user_login_failures_total", 
            "api_errors_total"
        ]
        
        available_metrics = []
        for metric in metrics_to_check:
            response = requests.get(f"http://localhost:9090/api/v1/query?query={metric}")
            data = response.json()
            if data['data']['result']:
                available_metrics.append(metric)
        
        print(f"✓ Available metrics: {len(available_metrics)}/{len(metrics_to_check)}")
        return len(available_metrics) > 0
        
    except Exception as e:
        print(f"✗ Metrics check failed: {e}")
        return False

def check_grafana():
    try:
        response = requests.get("http://localhost:3000/api/health")
        if response.status_code == 200:
            print("✓ Grafana: ACCESSIBLE")
            return True
        else:
            print("✗ Grafana: INACCESSIBLE")
            return False
    except Exception as e:
        print(f"✗ Grafana check failed: {e}")

        return False

def main():
    print("=== Monitoring System Verification ===\n")
    
    checks = [
        check_prometheus_targets,
        check_metrics_availability, 
        check_grafana
    ]
    
    results = []
    for check in checks:
        results.append(check())
    
    passed = sum(results)
    total = len(checks)
    
    print(f"\n=== Results: {passed}/{total} checks passed ===")
    
    if passed == total:
        print("✓ Monitoring system is fully operational")
        return 0
    else:
        print("✗ Monitoring system has issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())
