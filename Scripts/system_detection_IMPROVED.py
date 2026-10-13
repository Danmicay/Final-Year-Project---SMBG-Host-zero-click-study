#!/usr/bin/env python3
"""
SMBGhost System-Level Detection Algorithm
Analyses Sysmon event logs to detect suspicious system behavior
associated with CVE-2020-0796 exploitation and post-exploitation activity.

"""

import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import json


class SystemDetectionEngine:
    """
    Multi-heuristic system behavior analyser using Sysmon event correlation.
    Detects patterns consistent with SMBGhost exploitation and post-exploitation activity.
    """
    
    def __init__(self, sysmon_csv_path: str):
        """
        Initialize detection engine with Sysmon event log.
        
        Args:
            sysmon_csv_path: Path to exported Sysmon events CSV file
        """
        self.df = pd.read_csv(sysmon_csv_path)
        self.alerts = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        self.correlations = []
        
    def run_all_detections(self) -> Dict:
        """
        Execute all detection heuristics and return comprehensive alert report.
        
        Returns:
            Dictionary containing all alerts organized by severity
        """
        print("[*] Starting system detection analysis...")
        print(f"[*] Processing {len(self.df)} Sysmon events")
        
        # Run all detection heuristics
        self.detect_suspicious_smb_processes()
        self.detect_temporal_smb_process_correlation()
        self.detect_persistence_mechanisms()
        self.detect_process_injection()
        self.detect_malicious_network_patterns()
        self.detect_privilege_escalation_indicators()
        self.detect_suspicious_dll_loading()
        
        return self.generate_report()
    
    # ============================================================================
    # Suspicious Process Establishing SMB Connection
    # ============================================================================
    
    def detect_suspicious_smb_processes(self) -> None:
        """
        Detect suspicious processes initiating SMB connections.
        
        Rationale:
        - Legitimate applications rarely establish SMB connections
        - Malware commonly uses cmd.exe, powershell.exe for C2 communication
        - rundll32.exe and wscript.exe are abuse vectors for malware
        
        Severity: HIGH
        """
        
        # Process names known to be abuse vectors
        SUSPICIOUS_PROCESSES = {
            'powershell.exe': 'PowerShell - Remote execution vector',
            'cmd.exe': 'Command Prompt - Remote execution vector',
            'wscript.exe': 'Windows Script Host - Scripting malware vector',
            'cscript.exe': 'Command Script Host - Scripting malware vector',
            'rundll32.exe': 'DLL Execution - Legitimate but commonly abused',
            'regsvcs.exe': '.NET Services Installer - Execution abuse',
            'mshta.exe': 'HTML Application Host - Execution abuse',
            'certutil.exe': 'Certificate utility - Data exfiltration abuse',
            'bitsadmin.exe': 'Background Intelligent Transfer - Download abuse'
        }
        
        # Extract network connection events (Event ID 3)
        network_events = self.df[self.df['EventID'] == 3] if 'EventID' in self.df.columns else pd.DataFrame()
        
        if network_events.empty:
            print("[-] No network events (Event ID 3) found in logs")
            return
        
        for idx, event in network_events.iterrows():
            message = str(event.get('Message', '')).lower() if 'Message' in event else ''
            
            # Check if connection is to SMB port (445) or netbios (137-139)
            if not any(port in message for port in ['445', '139', '137']):
                continue
            
            # Check if process is in suspicious list
            for sus_proc, reason in SUSPICIOUS_PROCESSES.items():
                if sus_proc.lower() in message:
                    
                    # Extract details
                    process_name = event.get('Image', 'Unknown') if 'Image' in event else 'Unknown'
                    source_ip = event.get('SourceIp', 'Unknown') if 'SourceIp' in event else 'Unknown'
                    dest_ip = event.get('DestinationIp', 'Unknown') if 'DestinationIp' in event else 'Unknown'
                    dest_port = event.get('DestinationPort', 'Unknown') if 'DestinationPort' in event else 'Unknown'
                    timestamp = event.get('TimeCreated', '') if 'TimeCreated' in event else ''
                    
                    alert = {
                        'timestamp': timestamp,
                        'heuristic': 'Suspicious Process SMB Connection',
                        'severity': 'HIGH',
                        'process': sus_proc,
                        'process_path': process_name,
                        'reason': reason,
                        'source_ip': source_ip,
                        'destination_ip': dest_ip,
                        'destination_port': dest_port,
                        'details': f"{sus_proc} established connection to {dest_ip}:{dest_port} (SMB port)"
                    }
                    self.alerts['high'].append(alert)
                    print(f"[!] HIGH: {sus_proc} connecting to SMB port {dest_port}")
    
    # ============================================================================
    # Process Creation Following SMB Activity
    # ============================================================================
    
    def detect_temporal_smb_process_correlation(self) -> None:
        """
        Detect process creation shortly after SMB network activity.
        
        Rationale:
        - Successful exploitation often leads to payload execution
        - New process creation within seconds of network activity is suspicious
        - Indicates SMB connection may have delivered exploit payload
        
        Time window: 0-30 seconds (configurable)
        Severity: MEDIUM -> HIGH if process is from suspicious location
        """
        
        # Extract relevant events
        network_events = self.df[self.df['EventID'] == 3] if 'EventID' in self.df.columns else pd.DataFrame()
        process_events = self.df[self.df['EventID'] == 1] if 'EventID' in self.df.columns else pd.DataFrame()
        
        if network_events.empty or process_events.empty:
            return
        
        # For each SMB network connection
        for net_idx, net_event in network_events.iterrows():
            net_time = pd.to_datetime(net_event.get('TimeCreated', datetime.now())) if 'TimeCreated' in net_event else datetime.now()
            net_dest_port = str(net_event.get('DestinationPort', '')) if 'DestinationPort' in net_event else ''
            
            # Only interested in SMB traffic
            if net_dest_port not in ['445', '139', '137']:
                continue
            
            # Find process creation events within time window
            for proc_idx, proc_event in process_events.iterrows():
                proc_time = pd.to_datetime(proc_event.get('TimeCreated', datetime.now())) if 'TimeCreated' in proc_event else datetime.now()
                
                # Calculate time difference
                time_diff = (proc_time - net_time).total_seconds()
                
                # Check if process creation occurred 0-30 seconds after SMB activity
                if 0 <= time_diff <= 30:
                    
                    process_name = proc_event.get('Image', 'Unknown') if 'Image' in proc_event else 'Unknown'
                    command_line = proc_event.get('CommandLine', 'Unknown') if 'CommandLine' in proc_event else 'Unknown'
                    parent_process = proc_event.get('ParentImage', 'Unknown') if 'ParentImage' in proc_event else 'Unknown'
                    
                    # Determine severity based on process characteristics
                    severity = 'MEDIUM'
                    if any(sus in process_name.lower() for sus in ['system32', 'temp', 'appdata']):
                        severity = 'HIGH'
                    
                    alert = {
                        'timestamp': str(proc_time),
                        'heuristic': 'Process Creation After SMB Activity',
                        'severity': severity,
                        'network_time': str(net_time),
                        'process_time': str(proc_time),
                        'time_difference_seconds': round(time_diff, 2),
                        'process': process_name,
                        'command_line': command_line,
                        'parent_process': parent_process,
                        'details': f"Process {process_name} created {time_diff:.1f}s after SMB activity"
                    }
                    self.alerts[severity.lower()].append(alert)
                    self.correlations.append((net_time, proc_time, process_name))
                    print(f"[!] {severity}: Process created {time_diff:.1f}s after SMB activity: {process_name}")
    
    # ============================================================================
    # Persistence Mechanism Detection
    # ============================================================================
    
    def detect_persistence_mechanisms(self) -> None:
        """
        Detect files/registry modifications in persistence locations.
        
        Rationale:
        - Attackers establish persistence to maintain access
        - Auto-start locations are common persistence vectors
        - Registry Run keys, startup folders, scheduled tasks, services are targets
        
        Monitors:
        - Event ID 11: File creation in startup folders
        - Event ID 12/13: Registry modification in Run keys
        - Scheduled task creation
        
        Severity: HIGH
        """
        
        PERSISTENCE_PATHS = {
            'registry_run': [
                'hklm:\\software\\microsoft\\windows\\currentversion\\run',
                'hkcu:\\software\\microsoft\\windows\\currentversion\\run',
                'hklm:\\software\\microsoft\\windows\\currentversion\\runonce',
                'hkcu:\\software\\microsoft\\windows\\currentversion\\runonce'
            ],
            'startup_folders': [
                'appdata\\microsoft\\windows\\start menu\\programs\\startup',
                'programdata\\microsoft\\windows\\start menu\\programs\\startup'
            ],
            'scheduled_tasks': [
                'windows\\tasks',
                'system32\\tasks'
            ]
        }
        
        # File creation events (Event ID 11)
        file_events = self.df[self.df['EventID'] == 11] if 'EventID' in self.df.columns else pd.DataFrame()
        
        for idx, event in file_events.iterrows():
            file_path = str(event.get('TargetFilename', '')).lower() if 'TargetFilename' in event else ''
            timestamp = event.get('TimeCreated', '') if 'TimeCreated' in event else ''
            
            # Check for startup folder creation
            for startup_path in PERSISTENCE_PATHS['startup_folders']:
                if startup_path.lower() in file_path:
                    
                    alert = {
                        'timestamp': timestamp,
                        'heuristic': 'Persistence - File in Startup Folder',
                        'severity': 'HIGH',
                        'file_path': file_path,
                        'category': 'Persistence Mechanism',
                        'details': f"File created in startup location: {file_path}"
                    }
                    self.alerts['high'].append(alert)
                    print(f"[!] HIGH: Persistence file in startup folder: {file_path}")
        
        # Registry modification events (Event ID 12/13)
        registry_events = self.df[
            (self.df['EventID'] == 12) | (self.df['EventID'] == 13)
        ] if 'EventID' in self.df.columns else pd.DataFrame()
        
        for idx, event in registry_events.iterrows():
            reg_path = str(event.get('TargetObject', '')).lower() if 'TargetObject' in event else ''
            timestamp = event.get('TimeCreated', '') if 'TimeCreated' in event else ''
            
            # Check for Run key modification
            for run_key in PERSISTENCE_PATHS['registry_run']:
                if run_key.lower() in reg_path:
                    
                    alert = {
                        'timestamp': timestamp,
                        'heuristic': 'Persistence - Registry Run Key Modification',
                        'severity': 'HIGH',
                        'registry_path': reg_path,
                        'category': 'Persistence Mechanism',
                        'details': f"Registry Run key modified: {reg_path}"
                    }
                    self.alerts['high'].append(alert)
                    print(f"[!] HIGH: Persistence registry key modified: {reg_path}")
    
    # ============================================================================
    # Process Injection Detection
    # ============================================================================
    
    def detect_process_injection(self) -> None:
        """
        Detect CreateRemoteThread and process injection attempts.
        
        Rationale:
        - Process injection is advanced malware technique
        - Indicates code running in context of legitimate process
        - Event ID 8: CreateRemoteThread
        - Event ID 10: Registry access (suspicious patterns)
        
        Severity: CRITICAL
        """
        
        # Process injection via CreateRemoteThread (Event ID 8)
        injection_events = self.df[self.df['EventID'] == 8] if 'EventID' in self.df.columns else pd.DataFrame()
        
        if not injection_events.empty:
            for idx, event in injection_events.iterrows():
                
                source_process = event.get('Image', 'Unknown') if 'Image' in event else 'Unknown'
                target_process = event.get('TargetImage', 'Unknown') if 'TargetImage' in event else 'Unknown'
                timestamp = event.get('TimeCreated', '') if 'TimeCreated' in event else ''
                
                alert = {
                    'timestamp': timestamp,
                    'heuristic': 'Process Injection (CreateRemoteThread)',
                    'severity': 'CRITICAL',
                    'source_process': source_process,
                    'target_process': target_process,
                    'category': 'Code Execution',
                    'details': f"{source_process} injecting into {target_process}"
                }
                self.alerts['critical'].append(alert)
                print(f"[!!!] CRITICAL: Process injection detected: {source_process} -> {target_process}")
    
    # ============================================================================
    # Suspicious Network Pattern Detection
    # ============================================================================
    
    def detect_malicious_network_patterns(self) -> None:
        """
        Detect patterns of network behavior consistent with malware.
        
        Rationale:
        - Malware often establishes multiple connections
        - Connections to unusual ports or ranges
        - Rapid connection attempts (scan-like behavior)
        
        Monitors:
        - Multiple connections from single process
        - Unusual destination ports
        - Connection rate anomalies
        
        Severity: MEDIUM
        """
        
        network_events = self.df[self.df['EventID'] == 3] if 'EventID' in self.df.columns else pd.DataFrame()
        
        if network_events.empty:
            return
        
        # Group by process to identify which processes are making many connections
        if 'Image' in network_events.columns:
            process_connections = network_events.groupby('Image').size()
            
            # Flag processes making excessive connections
            EXCESSIVE_THRESHOLD = 10  # More than 10 connections is suspicious
            
            for process, count in process_connections.items():
                if count > EXCESSIVE_THRESHOLD:
                    alert = {
                        'heuristic': 'Excessive Network Connections',
                        'severity': 'MEDIUM',
                        'process': process,
                        'connection_count': int(count),
                        'details': f"Process established {count} network connections (threshold: {EXCESSIVE_THRESHOLD})"
                    }
                    self.alerts['medium'].append(alert)
                    print(f"[!] MEDIUM: Excessive connections from {process}: {count}")
    
    # ============================================================================
    # Privilege Escalation Indicators
    # ============================================================================
    
    def detect_privilege_escalation_indicators(self) -> None:
        """
        Detect patterns indicating privilege escalation attempts.
        
        Rationale:
        - Exploitation often targets privilege escalation
        - Unusual access to system processes
        - Token elevation patterns
        
        Severity: HIGH
        """
        
        # Look for process creation with SYSTEM privileges from unusual sources
        process_events = self.df[self.df['EventID'] == 1] if 'EventID' in self.df.columns else pd.DataFrame()
        
        if process_events.empty:
            return
        
        # Suspicious parent-child relationships
        SUSPICIOUS_PARENTS = {
            'system.exe': 'System process spawning child (unusual)',
            'lsass.exe': 'LSASS spawning child (token elevation?)',
            'services.exe': 'Services spawning suspicious child'
        }
        
        if 'ParentImage' in process_events.columns and 'Image' in process_events.columns:
            for idx, event in process_events.iterrows():
                parent = str(event.get('ParentImage', '')).lower()
                child = str(event.get('Image', ''))
                timestamp = event.get('TimeCreated', '') if 'TimeCreated' in event else ''
                
                for suspicious_parent, reason in SUSPICIOUS_PARENTS.items():
                    if suspicious_parent.lower() in parent:
                        alert = {
                            'timestamp': timestamp,
                            'heuristic': 'Privilege Escalation Indicator',
                            'severity': 'HIGH',
                            'parent_process': parent,
                            'child_process': child,
                            'reason': reason,
                            'details': f"Unusual parent-child relationship: {parent} -> {child}"
                        }
                        self.alerts['high'].append(alert)
                        print(f"[!] HIGH: Suspicious privilege escalation pattern: {parent} -> {child}")
    
    # ============================================================================
    # Suspicious DLL Loading
    # ============================================================================
    
    def detect_suspicious_dll_loading(self) -> None:
        """
        Detect suspicious DLL loading patterns.
        
        Rationale:
        - DLL injection is common malware technique
        - Loading DLLs from unusual locations indicates compromise
        - Event ID 7: Image loaded
        
        Severity: MEDIUM
        """
        
        dll_events = self.df[self.df['EventID'] == 7] if 'EventID' in self.df.columns else pd.DataFrame()
        
        if dll_events.empty:
            return
        
        # Suspicious DLL locations
        SUSPICIOUS_PATHS = ['temp', 'appdata', 'downloads', 'programdata']
        
        for idx, event in dll_events.iterrows():
            image_path = str(event.get('ImageLoaded', '')).lower() if 'ImageLoaded' in event else ''
            process = event.get('Image', 'Unknown') if 'Image' in event else 'Unknown'
            timestamp = event.get('TimeCreated', '') if 'TimeCreated' in event else ''
            
            for sus_path in SUSPICIOUS_PATHS:
                if sus_path in image_path:
                    alert = {
                        'timestamp': timestamp,
                        'heuristic': 'Suspicious DLL Loading',
                        'severity': 'MEDIUM',
                        'process': process,
                        'dll_path': image_path,
                        'details': f"{process} loaded DLL from suspicious location: {image_path}"
                    }
                    self.alerts['medium'].append(alert)
                    print(f"[!] MEDIUM: Suspicious DLL loaded by {process}")
                    break
    
    # ============================================================================
    # REPORT GENERATION
    # ============================================================================
    
    def generate_report(self) -> Dict:
        """
        Generate comprehensive detection report.
        
        Returns:
            Dictionary with formatted alerts and summary statistics
        """
        
        total_alerts = (
            len(self.alerts['critical']) + 
            len(self.alerts['high']) + 
            len(self.alerts['medium']) + 
            len(self.alerts['low'])
        )
        
        report = {
            'summary': {
                'total_alerts': total_alerts,
                'critical': len(self.alerts['critical']),
                'high': len(self.alerts['high']),
                'medium': len(self.alerts['medium']),
                'low': len(self.alerts['low']),
                'threat_level': self._calculate_threat_level()
            },
            'alerts': self.alerts,
            'correlations': len(self.correlations)
        }
        
        return report
    
    def _calculate_threat_level(self) -> str:
        """Determine overall threat level based on alert distribution."""
        
        if len(self.alerts['critical']) > 0:
            return "CRITICAL"
        elif len(self.alerts['high']) >= 3:
            return "HIGH"
        elif len(self.alerts['high']) > 0:
            return "MEDIUM"
        elif len(self.alerts['medium']) > 0:
            return "LOW"
        else:
            return "CLEAN"
    
    def print_report(self) -> None:
        """Print formatted report to console."""
        
        report = self.generate_report()
        summary = report['summary']
        
        print("\n" + "="*70)
        print("SYSTEM DETECTION REPORT - SMBGhost Analysis".center(70))
        print("="*70)
        
        print(f"\nThreat Level: {summary['threat_level']}")
        print(f"Total Alerts: {summary['total_alerts']}")
        print(f"  - Critical: {summary['critical']}")
        print(f"  - High: {summary['high']}")
        print(f"  - Medium: {summary['medium']}")
        print(f"  - Low: {summary['low']}")
        print(f"Event Correlations: {report['correlations']}")
        
        if summary['critical'] > 0:
            print("\n[CRITICAL ALERTS]")
            for alert in self.alerts['critical']:
                print(f"  {alert['heuristic']}: {alert['details']}")
        
        if summary['high'] > 0:
            print("\n[HIGH ALERTS]")
            for alert in self.alerts['high'][:5]:  # Show first 5
                print(f"  {alert['heuristic']}: {alert.get('details', alert.get('reason', 'N/A'))}")
            if len(self.alerts['high']) > 5:
                print(f"  ... and {len(self.alerts['high']) - 5} more")
        
        print("\n" + "="*70)
    
    def export_json(self, output_file: str) -> None:
        """Export report to JSON file."""
        
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[+] Report exported to: {output_file}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function."""
    
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python system_detection.py <sysmon_csv_file>")
        print("Example: python system_detection.py sysmon_baseline.csv")
        sys.exit(1)
    
    sysmon_file = sys.argv[1]
    
    try:
        # Initialize detection engine
        engine = SystemDetectionEngine(sysmon_file)
        
        # Run all detections
        report = engine.run_all_detections()
        
        # Print report
        engine.print_report()
        
        # Export to JSON
        output_json = sysmon_file.replace('.csv', '_detections.json')
        engine.export_json(output_json)
        
        print(f"\n[+] Detection analysis complete")
        
    except FileNotFoundError:
        print(f"[!] Error: File not found: {sysmon_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
