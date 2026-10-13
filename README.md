Simulation Framework for Zero-Click Attacks

A safe, reproducible VM-based framework for studying zero-click attack behaviour and building multi-layer detection for it, using synthetic, non-malicious traffic modelled on SMBGhost (CVE-2020-0796).

Built as my final year project for a BSc (Hons) Cyber Security degree at De Montfort University (First Class), supervised by Debalina Padariya.

No exploit code lives in this repository. Nothing here can compromise a system. See Ethics and safety.

Why this exists

Zero-click attacks need no user interaction. They target code that automatically parses incoming data, so user awareness training does nothing against them. Pegasus, FORCEDENTRY and KISMET showed that even security-conscious users can be compromised without noticing.

The problem for researchers is that these attacks are hard to study. Real exploits raise ethical and legal issues, vendor patches remove the vulnerable code paths quickly, and most existing simulation platforms assume a user or an explicit trigger. The result is plenty of post-incident writing and very little reproducible experimentation.

This project closes part of that gap. Instead of running a real exploit, it simulates the observable behaviour of an SMBGhost-style attack and measures how a vulnerable host and a patched host respond.

About the target: SMBGhost (CVE-2020-0796)

SMBGhost is an integer overflow in the SMBv3.1.1 compression handling in srv2.sys, which can lead to a buffer overflow in kernel context. It affects Windows 10 1903 and 1909, carries a CVSS score of 10.0, and was patched by Microsoft in KB4551762. It is pre-authentication, network reachable on TCP 445, and needs no user action, which makes it a textbook zero-click case.

How it works

Identical test traffic is sent to two VMs, and the same telemetry is collected from both.

OS	Windows 10 Education 1909 (Build 18363.418)	Windows 10 22H2 (Build 19045.3803)
Address	192.168.10.10	192.168.10.20
Spec	2 vCPU, 2 GB RAM, 60 GB disk	2 vCPU, 2 GB RAM, 60 GB disk
Network	VMware Host-Only, no internet or campus access	VMware Host-Only, no internet or campus access

Both machines are configured identically apart from patch level, so any behavioural difference can be attributed to the update rather than environmental noise.

Traffic generation

Python and Scapy generate SMB packets that mimic the structure of SMBGhost exploitation, for example malformed compression headers and unusual packet layouts, carrying harmless filler data. The goal is to push the target's SMB processing path and observe how it reacts, not to gain code execution.

Three detection layers
Network layer. Packet captures (Wireshark, Scapy) are inspected for malformed SMB compression headers, invalid compression algorithm values, abnormal packet sizes and irregular SMB traffic patterns on port 445.
System layer. Sysmon telemetry and Windows event logs are correlated with network activity: process creation after SMB events, network connections, file and registry changes, driver loads, and anything pointing at srv2.sys.
Behavioural layer. Post-test system state is compared to a pre-test baseline, and statistical anomaly detection (Z-score based) flags deviations from normal.

Detection confidence is meant to increase when more than one layer fires, which is the defence-in-depth idea behind the design.

Baselines

baseline_collect.ps1 snapshots both VMs before any test traffic is sent, so there is a known-good reference to compare against:

running processes (PID, parent/child, command line, user, start time)
services and startup type
active connections and listening ports
SMB configuration (versions, signing, encryption, compression status)
scheduled tasks, installed software and startup programs
recent Security events and an initial Sysmon log export
Benchmarking

The project plan includes comparing the framework's detection performance against established IDS tooling (Snort and Suricata) on the same traffic.

Tech stack
Python 3.11: Scapy (packet crafting and analysis), pandas (data handling), matplotlib (visualisation)
PowerShell: baseline collection
Sysmon + Sysinternals Suite (including Process Monitor): endpoint telemetry
Wireshark: packet capture and SMB inspection
VMware Workstation: isolated, snapshot-able lab

Getting started
Prerequisites
A host able to run two Windows 10 VMs in VMware Workstation
Windows 10 1909 and 22H2 installation media from a legitimate, licensed source
Python 3.11+ on the host
Lab setup (summary)
Create two VMs and attach both to a Host-Only network with no bridge or NAT.
On the vulnerable VM, install Windows 10 1909, disable Windows Update, confirm SMBv3 is enabled and set the static IP. Do not patch it.
On the patched VM, install 22H2 with current updates.
Install Sysmon on both and confirm events appear under Applications and Services Logs > Microsoft > Windows > Sysmon > Operational.
Take a clean snapshot of each VM, then run baseline_collect.ps1 and copy the output to the host.
Only then run any traffic generation, and take snapshots between stages.
Running the host-side tooling

Run the generators and analysis scripts from the host against the Host-Only addresses. Script usage is documented in documentation/.

Ethics and safety
Synthetic only. The framework sends malformed-looking but inert packets. It does not contain, reproduce or distribute exploit code.
Isolated by design. Both VMs sit on a Host-Only network with no route to the internet, a university network or any real system.
Approved. The synthetic approach is what my university ethics approval was granted on.
Legitimate software. The Windows 10 1909 ISO came from the university IT department under proper licensing.
Recoverable. Snapshots are taken at each stage, and results are copied to the host straight away.

If you reproduce this work, keep the same isolation and use only licensed software.

Limitations

Being honest about what this approach cannot do:

It cannot tell you how reliable a real SMBGhost exploit is.
It may miss post-exploitation behaviour that only genuine code execution would produce. Persistence and follow-on activity are simulated, not real.
During testing, the operating system filtered the malformed traffic at kernel level, so the vulnerable and patched hosts did not diverge as dramatically at the application layer as a real exploit might suggest. I treat that as evidence the OS defences work, but it does limit what can be inferred about the exploit path itself.
Two small VMs limit the scale of traffic that can be simulated.
Future work
Extend the simulation model to other zero-click surfaces (messaging, media parsers, baseband-style protocol handling)
Longer-running tests focused on persistence and detection latency
Tighter comparison with Snort and Suricata rule sets, including custom rules derived from this framework's findings
Key references
Citizen Lab (2021), FORCEDENTRY: NSO Group iMessage Zero-Click Exploit Captured in the Wild
Marczak et al. (2020), The Great iPwn (KISMET)
Groß, S. (2021), A look at iMessage in iOS 14, Google Project Zero
Project Zero (2023), Multiple Internet-to-Baseband Remote Code Execution Vulnerabilities in Samsung Exynos
Scarfone and Mell (2012), Guide to Intrusion Detection and Prevention Systems, NIST SP 800-94 Rev. 1
Microsoft Security Advisory ADV200005 and CVE-2020-0796, plus technical write-ups from Cisco Talos, Check Point and ZecOps
Disclaimer

This repository is for education and defensive research only. Do not use it, or anything derived from it, against systems you do not own or have explicit written permission to test.

Author

Daniel Gray, BSc (Hons) Cyber Security, De Montfort University

Supervisor: Debalina Padariya
