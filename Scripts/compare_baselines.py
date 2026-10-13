import pandas as pd
import os

def compare_baselines(before_folder, after_folder, output_file):
    """
    Compares before and after baseline data
    """
    print(f"\n{'='*60}")
    print(f"BASELINE COMPARISON")
    print(f"{'='*60}")
    print(f"Before: {before_folder}")
    print(f"After:  {after_folder}")
    
    results = []
    
    # Compare processes
    print("\n[*] Comparing processes...")
    before_proc = pd.read_csv(os.path.join(before_folder, "processes.csv"))
    after_proc = pd.read_csv(os.path.join(after_folder, "processes.csv"))
    
    before_names = set(before_proc['ProcessName'].dropna())
    after_names = set(after_proc['ProcessName'].dropna())
    
    new_processes = after_names - before_names
    stopped_processes = before_names - after_names
    
    results.append(f"\n--- Process Changes ---")
    results.append(f"New processes: {len(new_processes)}")
    for proc in new_processes:
        results.append(f"  + {proc}")
    results.append(f"Stopped processes: {len(stopped_processes)}")
    for proc in stopped_processes:
        results.append(f"  - {proc}")
    
    # Compare network connections
    print("[*] Comparing network connections...")
    # (Network connections file is text, not CSV)
    
    # Save results
    with open(output_file, 'w') as f:
        f.write('\n'.join(results))
    
    print(f"\n[✓] Comparison saved to: {output_file}")
    print('\n'.join(results))

# Run comparisons
print("\n" + "="*60)
print("VULNERABLE VM COMPARISON")
print("="*60)
compare_baselines(
    "C:/ZeroClick_Project/Data/Baselines/Vulnerable/Vulnerable_Initial_Baseline",
    "C:/ZeroClick_Project/Data/Baselines/Vulnerable/Vulnerable_After_Test1",
    "C:/ZeroClick_Project/Data/TestResults/vulnerable_comparison.txt"
)

print("\n" + "="*60)
print("PATCHED VM COMPARISON")
print("="*60)
compare_baselines(
    "C:/ZeroClick_Project/Data/Baselines/Patched/Patched_Initial_Baseline",
    "C:/ZeroClick_Project/Data/Baselines/Patched/Patched_After_Test1",
    "C:/ZeroClick_Project/Data/TestResults/patched_comparison.txt"
)