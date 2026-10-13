import pandas as pd
import os

def analyse_sysmon_logs(baseline_folder, vm_name):
    """
    analyses Sysmon logs for suspicious activity
    """
    print(f"\n{'='*60}")
    print(f"SYSMON ANALYSIS - {vm_name}")
    print(f"{'='*60}")
    
    sysmon_file = os.path.join(baseline_folder, "sysmon_baseline.csv")
    
    if not os.path.exists(sysmon_file):
        print(f"[!] Sysmon file not found: {sysmon_file}")
        return
    
    try:
        df = pd.read_csv(sysmon_file)
        print(f"\n[*] Total Sysmon events: {len(df)}")
        
        # Count events by ID
        print("\n--- Event Distribution ---")
        if 'Id' in df.columns:
            event_counts = df['Id'].value_counts()
            for event_id, count in event_counts.items():
                print(f"Event ID {event_id}: {count} events")
        
        # Look for network events (Event ID 3)
        if 'Id' in df.columns:
            network_events = df[df['Id'] == 3]
            print(f"\n[*] Network connection events: {len(network_events)}")
            
            if len(network_events) > 0:
                print("\nRecent network connections:")
                print(network_events[['TimeCreated', 'Message']].head())
        
    except Exception as e:
        print(f"[!] Error analyzing Sysmon logs: {e}")

# analyse both VMs
analyse_sysmon_logs(
    "C:/ZeroClick_Project/Data/Baselines/Vulnerable/Vulnerable_After_Test1",
    "Vulnerable VM"
)

analyse_sysmon_logs(
    "C:/ZeroClick_Project/Data/Baselines/Patched/Patched_After_Test1",
    "Patched VM"
)