
"""
Tatou Security Incident Drill Script
Simulates security incidents to test response procedures and team readiness.
"""
import random
import time
import json
import argparse
from datetime import datetime

class IncidentDrill:
    def __init__(self):
        self.drill_id = f"drill_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results = {
            'drill_id': self.drill_id,
            'start_time': datetime.now().isoformat(),
            'scenarios': [],
            'results': {}
        }
    
    def log_scenario(self, name, description, steps):
        """Log a drill scenario"""
        scenario = {
            'name': name,
            'description': description,
            'steps': steps,
            'start_time': datetime.now().isoformat()
        }
        self.results['scenarios'].append(scenario)
        return scenario
    
    def simulate_brute_force_attack(self):
        """Simulate brute force attack scenario"""
        print("\n DRILL SCENARIO: Brute Force Attack Detection")
        print("Description: Multiple failed login attempts from a single IP address")

        steps = [
            "1. Monitor for failed login attempts in logs and metrics",
            "2. Identify the source IP address of the attacks", 
            "3. Check if rate limiting is triggered",
            "4. Verify alerting rules are working",
            "5. Document the incident and response actions"
        ]
        
        scenario = self.log_scenario(
            "Brute Force Attack",
            "Multiple failed login attempts from a single IP",
            steps
        )
        
        print("Steps to execute:")
        for step in steps:
            print(f"  {step}")
        
        # Simulate some time for the team to perform actions
        input("\n Press Enter when your team has completed the response steps...")
        
        # Debrief
        print("\n DEBRIEFING QUESTIONS:")
        debrief_questions = [
            "Were the failed logins detected promptly?",
            "Was the source IP correctly identified?",
            "Did rate limiting work as expected?",
            "Were alerts generated and noticed?",
            "What improvements are needed in detection or response?"
        ]
        
        for q in debrief_questions:
            response = input(f"  {q}\n    Your notes: ")
            # Store responses if needed
        
        scenario['end_time'] = datetime.now().isoformat()
        print(" Brute force attack drill completed")
    
    def simulate_flag_compromise(self):
        """Simulate flag file compromise scenario"""
        print("\n DRILL SCENARIO: Flag File Compromise")
        print("Description: Unauthorized access to container flag file detected")
        
        steps = [
            "1. Verify which flag file was accessed",
            "2. Check container logs for access patterns",
            "3. Identify potential vulnerability exploited",
            "4. Regenerate compromised flags",
            "5. Post disclosure on course forum",
            "6. Implement additional access controls"
        ]
        
        scenario = self.log_scenario(
            "Flag Compromise", 
            "Unauthorized access to flag file",
            steps
        )
        
        print("Steps to execute:")
        for step in steps:
            print(f"  {step}")
        
        input("\n Press Enter when your team has completed the response steps...")
        
        print("\n DEBRIEFING QUESTIONS:")
        debrief_questions = [
            "How was the flag access detected?",
            "What vulnerability was exploited?",
            "Were logs sufficient to trace the attack?",
            "How quickly were flags regenerated?",
            "What additional controls were implemented?"
        ]
        
        for q in debrief_questions:
            response = input(f"  {q}\n    Your notes: ")
        
        scenario['end_time'] = datetime.now().isoformat()
        print(" Flag compromise drill completed")
    
    def simulate_watermark_tampering(self):
        """Simulate watermark tampering scenario"""
        print("\n DRILL SCENARIO: Watermark Tampering")
        print("Description: Suspicious watermark read failures and tampering attempts")
        
        steps = [
            "1. Analyze watermark read error patterns",
            "2. Identify affected documents and users", 
            "3. Check for watermark algorithm vulnerabilities",
            "4. Verify document integrity checks",
            "5. Enhance watermark validation if needed"
        ]
        
        scenario = self.log_scenario(
            "Watermark Tampering",
            "Suspicious watermark read failures and tampering",
            steps
        )
        
        print("Steps to execute:")
        for step in steps:
            print(f"  {step}")
        
        input("\n Press Enter when your team has completed the response steps...")
        
        print("\n DEBRIEFING QUESTIONS:")
        debrief_questions = [
            "How were the tampering attempts detected?",
            "Which watermark methods were affected?",
            "Were there any successful tampering?",
            "What improvements to watermarking are needed?",
            "How can detection be improved?"
        ]
        
        for q in debrief_questions:
            response = input(f"  {q}\n    Your notes: ")
        
        scenario['end_time'] = datetime.now().isoformat()
        print(" Watermark tampering drill completed")

    def run_drill(self, scenario_name=None):
        """Run the specified drill scenario or choose randomly"""
        scenarios = {
            'brute_force': self.simulate_brute_force_attack,
            'flag_compromise': self.simulate_flag_compromise, 
            'watermark_tampering': self.simulate_watermark_tampering
        }
        
        if scenario_name and scenario_name in scenarios:
            scenarios[scenario_name]()
        else:
            # Choose random scenario
            scenario = random.choice(list(scenarios.keys()))
            print(f" Randomly selected scenario: {scenario}")
            scenarios[scenario]()
    
    def save_results(self):
        """Save drill results to file"""
        self.results['end_time'] = datetime.now().isoformat()
        
        filename = f"logs/incident_drill_{self.drill_id}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n Drill results saved to: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='Tatou Security Incident Drill')
    parser.add_argument('--scenario', choices=['brute_force', 'flag_compromise', 'watermark_tampering'],
                       help='Specific scenario to run')
    
    args = parser.parse_args()
    
    print("  Starting Tatou Security Incident Drill")
    print("==========================================")
    
    drill = IncidentDrill()
    
    try:
        drill.run_drill(args.scenario)
        results_file = drill.save_results()
        
        print("\n DRILL COMPLETED SUCCESSFULLY!")
        print("Review the drill results and discuss improvements with your team.")
        
    except KeyboardInterrupt:
        print("\n Drill interrupted by user")
    except Exception as e:
        print(f"\n Drill failed with error: {e}")

if __name__ == "__main__":
    main()
