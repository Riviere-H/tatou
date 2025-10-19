#!/usr/bin/env python3
"""
Enhanced Dependency Analysis Script
Analyze and document system dependencies with asset tracking
"""
import subprocess
import json
import yaml
import sys
import socket
from pathlib import Path

def parse_dependency_version(dep_string):
    """Parse dependencies"""
    dep_string = dep_string.strip('" ')
    if '@' in dep_string:
        return dep_string.split('@')[0], 'git'
    elif '==' in dep_string:
        parts = dep_string.split('==', 1)
        return parts[0].strip(), parts[1].strip()
    elif '>=' in dep_string:
        parts = dep_string.split('>=', 1)
        return parts[0].strip(), f">={parts[1].strip()}"
    else:
        return dep_string, 'unknown'

def get_python_dependencies():
    """Extract Python dependencies from pyproject.toml"""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        with open("server/pyproject.toml", "rb") as f:
            data = tomllib.load(f)
            
        dependencies = []
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            name, version = parse_dependency_version(dep)
            # Determine criticality
            criticality = determine_dependency_criticality(name)

            dependencies.append({
                'asset_id': f"DEP-{len(dependencies)+1:03d}",
                'name': name,
                'version': version,
                'type': 'python',
                'source': 'pyproject.toml',
                'criticality': criticality
            })
        
        return dependencies
    except Exception as e:
        print(f"Error reading Python dependencies: {e}")
        return []

def get_docker_dependencies():
    """Extract Docker image dependencies"""
    try:
        with open('docker-compose.yml', 'r') as f:
            compose_config = yaml.safe_load(f)
        
        dependencies = []
        for service_name, service_config in compose_config.get('services', {}).items():
            image = service_config.get('image', '')
            if image:
                if ':' in image:
                    name, version = image.split(':', 1)
                else:
                    name = image
                    version = 'latest'
                
                criticality = determine_service_criticality(service_name)
                
                dependencies.append({
                    'asset_id': f"DC-{service_name.upper()}",
                    'name': name,
                    'version': version,
                    'type': 'docker',
                    'service': service_name,
                    'criticality': criticality
                })
        
        return dependencies
    except Exception as e:
        print(f"Error reading Docker dependencies: {e}")
        return []

def determine_dependency_criticality(dep_name):
    """Determine criticality level for dependencies"""
    critical_deps = ['flask', 'pymupdf', 'rmap', 'pymysql', 'sqlalchemy']
    high_deps = ['gunicorn', 'werkzeug', 'itsdangerous']
    
    dep_lower = dep_name.lower()
    if any(critical in dep_lower for critical in critical_deps):
        return 'Critical'
    elif any(high in dep_lower for high in high_deps):
        return 'High'
    else:
        return 'Medium'

def determine_service_criticality(service_name):
    """Determine criticality level for services"""
    if service_name == 'db':
        return 'Critical'
    elif service_name == 'server':
        return 'High'
    else:
        return 'Medium'

def check_network_accessibility():
    """Check network port accessibility"""
    print(" Checking network accessibility...")
    
    port_checks = [
        ('Flask Application', '127.0.0.1', 5000),
        ('Database', '127.0.0.1', 3306),
        ('phpMyAdmin', '127.0.0.1', 8080)
    ]
    
    accessibility_results = []
    
    for service, host, port in port_checks:
        try:
            with socket.create_connection((host, port), timeout=2):
                status = 'accessible'
                print(f" {service} ({host}:{port}) - accessible")
        except Exception as e:
            status = f"inaccessible: {e}"
            print(f" {service} ({host}:{port}) - inaccessible")
        
        accessibility_results.append({
            'service': service,
            'host': host,
            'port': port,
            'status': status
        })
    
    return accessibility_results

def check_vulnerabilities(dependencies):
    """Enhanced vulnerability check with asset tracking"""
    # Known vulnerable versions (simplified - in production use safety/trivy)
    known_vulnerable_versions = {
        'flask': ['<2.0.0'],
        'sqlalchemy': ['<1.4.0'],
        'pymysql': ['<1.0.0']
    }
    
    for dep in dependencies:
        dep_name = dep['name'].lower()
        if dep_name in known_vulnerable_versions:
            vulnerable_versions = known_vulnerable_versions[dep_name]
            dep['vulnerability_check'] = {
                'status': 'warning',
                'message': f'Check for versions {vulnerable_versions}',
                'risk_level': 'Medium'
            }
        else:
            dep['vulnerability_check'] = {
                'status': 'unknown',
                'message': 'Manual verification required',
                'risk_level': 'Low'
            }
    
    return dependencies

def generate_asset_dependency_dot():
    """Generate a DOT format graph of asset dependencies"""
    print(" Generating asset dependency graph...")
    
    dot_content = [
        'digraph AssetDependencies {',
        'rankdir=LR;',
        'node [shape=box, style=filled];',
        ''
    ]
    
    # Color coding based on criticality
    color_map = {
        'Critical': 'red',
        'High': 'orange', 
        'Medium': 'yellow',
        'Low': 'green'
    }
    
    # Add critical assets
    dot_content.append('// Critical Assets')
    dot_content.extend([
        f'"{asset_id}" [label="{name}\\n({asset_id})", fillcolor="{color_map[criticality]}"];'
        for asset_id, name, criticality in [
            ('DB-001', 'MariaDB Database', 'Critical'),
            ('SEC-002', 'GPG Keys', 'Critical'),
            ('SEC-003', 'JWT Secrets', 'Critical'),
            ('SEC-005', 'Flag Files', 'Critical')
        ]
    ])
    
    dot_content.append('')
    dot_content.append('// High Assets') 
    dot_content.extend([
        f'"{asset_id}" [label="{name}\\n({asset_id})", fillcolor="{color_map[criticality]}"];'
        for asset_id, name, criticality in [
            ('APP-001', 'Flask Application', 'High'),
            ('APP-002', 'Gunicorn Server', 'High'),
            ('WM-001', 'Phantom Watermark', 'High'),
            ('AUTH-001', 'JWT System', 'High'),
            ('AUTH-002', 'RMAP Protocol', 'High')
        ]
    ])
    
    dot_content.append('')
    dot_content.append('// Medium Assets')
    dot_content.extend([
        f'"{asset_id}" [label="{name}\\n({asset_id})", fillcolor="{color_map[criticality]}"];'
        for asset_id, name, criticality in [
            ('DB-002', 'phpMyAdmin', 'Medium'),
            ('MON-001', 'Prometheus', 'Medium'),
            ('MON-002', 'Grafana', 'Medium'),
            ('FS-001', 'Original PDFs', 'Medium'),
            ('FS-002', 'Watermarked PDFs', 'Medium')
        ]
    ])
    
    # Add dependencies 
    dot_content.extend([
        '',
        '// Critical Dependencies',
        'APP-001 -> DB-001 [label="database access"];',
        'APP-001 -> SEC-003 [label="token validation"];', 
        'AUTH-002 -> SEC-002 [label="GPG encryption"];',
        '',
        '// High Dependencies',
        'APP-002 -> APP-001 [label="serves"];',
        'WM-001 -> APP-001 [label="integrated"];',
        'AUTH-001 -> APP-001 [label="protects"];',
        '',
        '// Medium Dependencies',
        'DB-002 -> DB-001 [label="manages"];',
        'MON-001 -> APP-001 [label="monitors"];',
        'MON-002 -> MON-001 [label="visualizes"];',
        'FS-001 -> APP-001 [label="stores"];',
        'FS-002 -> WM-001 [label="output"];'
    ])
    
    dot_content.extend(['', '}'])
    
    # Make sure directory exists 
    Path('docs').mkdir(exist_ok=True)
    Path('docs/asset_dependencies.dot').write_text('\n'.join(dot_content))
    print(" Asset dependency DOT graph generated: docs/asset_dependencies.dot")
    print("  You can generate SVG manually: dot -Tsvg docs/asset_dependencies.dot -o docs/asset_dependencies.svg")

def generate_dependency_graph(dependencies):
    """Generate dependency graph data for visualization"""
    graph_data = {
        'nodes': [],
        'edges': []
    }
    
    # Add nodes
    for dep in dependencies:
        graph_data['nodes'].append({
            'id': dep['asset_id'],
            'label': f"{dep['name']} ({dep['version']})",
            'type': dep['type'],
            'criticality': dep['criticality']
        })
    
    # Add edges (simplified - connect services to their dependencies)
    for dep in dependencies:
        if dep['type'] == 'docker' and dep['service'] == 'server':
            # Connect server to its Python dependencies
            for python_dep in [d for d in dependencies if d['type'] == 'python']:
                graph_data['edges'].append({
                    'from': dep['asset_id'],
                    'to': python_dep['asset_id'],
                    'relationship': 'depends_on'
                })
    
    return graph_data

def generate_dependency_report():
    """Generate comprehensive dependency report"""
    print(" Analyzing system dependencies...")
    
    python_deps = get_python_dependencies()
    docker_deps = get_docker_dependencies()
    network_status = check_network_accessibility()
    
    all_dependencies = python_deps + docker_deps
    all_dependencies = check_vulnerabilities(all_dependencies)
    
    # Generate dependency graph
    dependency_graph = generate_dependency_graph(all_dependencies)
    
    # Generate report
    report = {
        'timestamp': subprocess.getoutput('date -Iseconds'),
        'metadata': {
            'total_dependencies': len(all_dependencies),
            'python_dependencies': len(python_deps),
            'docker_dependencies': len(docker_deps),
            'critical_dependencies': len([d for d in all_dependencies if d['criticality'] == 'Critical']),
            'high_dependencies': len([d for d in all_dependencies if d['criticality'] == 'High'])
        },
        'network_accessibility': network_status,
        'dependencies': all_dependencies,
        'dependency_graph': dependency_graph
    }
    
    # Save reports
    Path('logs').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)
    
    with open('logs/dependency_analysis.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Save graph-friendly dependency list
    with open('logs/dependency_list.txt', 'w') as f:
        for dep in all_dependencies:
            f.write(f"{dep['type']}::{dep['name']}::{dep['version']}::{dep['criticality']}\n")
    
    # Save graph data for visualization
    with open('logs/dependency_graph.json', 'w') as f:
        json.dump(dependency_graph, f, indent=2)
    
    print(f" Dependency analysis completed: logs/dependency_analysis.json")

    generate_asset_dependency_dot()
    
    # Print summary
    print(f"\n Enhanced Dependency Summary:")
    print(f"  Total dependencies: {len(all_dependencies)}")
    print(f"  Critical dependencies: {report['metadata']['critical_dependencies']}")
    print(f"  High dependencies: {report['metadata']['high_dependencies']}")
    print(f"  Network services checked: {len(network_status)}")
    
    return report

if __name__ == "__main__":
    report = generate_dependency_report()
    sys.exit(0)
