def detect_suspicious_smb_activity(sysmon_csv_path):
    """
    Detects suspicious SMB-related activity in Sysmon logs
    """
    import pandas as pd
    
    df = pd.read_csv(sysmon_csv_path)
    alerts = []
    
    # Heuristic 1: Suspicious process establishing SMB connection
    suspicious_processes = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'rundll32.exe']
    network_events = df[df['Id'] == 3]  # Event ID 3: Network connection
    
    for idx, event in network_events.iterrows():
        message = str(event['Message']).lower()
        
        # Check if connection is to SMB port
        if '445' in message:
            for sus_proc in suspicious_processes:
                if sus_proc in message:
                    alerts.append({
                        'time': event['TimeCreated'],
                        'process': sus_proc,
                        'type': 'Suspicious Process SMB Connection',
                        'severity': 'HIGH'
                    })
    
    # Heuristic 2: Process creation following SMB activity
    process_events = df[df['Id'] == 1]  # Event ID 1: Process creation
    
    for idx, net_event in network_events.iterrows():
        net_time = pd.to_datetime(net_event['TimeCreated'])
        
        # Find process creations within 30 seconds of SMB activity
        for proc_idx, proc_event in process_events.iterrows():
            proc_time = pd.to_datetime(proc_event['TimeCreated'])
            time_diff = abs((proc_time - net_time).total_seconds())
            
            if time_diff <= 30:
                alerts.append({
                    'network_time': net_time,
                    'process_time': proc_time,
                    'time_difference': time_diff,
                    'type': 'Process Creation After SMB Activity',
                    'severity': 'MEDIUM'
                })
    
    return alerts