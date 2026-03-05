# Microsoft Defender for Endpoint - Safe Alert Simulation

> **Purpose:** Generate REAL alerts in Microsoft Defender for Endpoint (MDE) for educational demos without infecting or damaging the machine.

## MITRE ATT&CK Kill Chain Coverage

The script walks through all 12 phases of a simulated attack, mapped to MITRE ATT&CK:

| # | Kill Chain Phase | MITRE Tactic | Techniques Used | What It Does |
|---|-----------------|--------------|-----------------|--------------|
| 1 | **Reconnaissance** | TA0043 | T1046, T1018 | Local port scan, ARP table enumeration |
| 2 | **Initial Access** | TA0001 | T1566.001, T1204.002 | EICAR test file, Microsoft's official MDE test command |
| 3 | **Execution** | TA0002 | T1059.001, T1059.003 | Base64-encoded PowerShell, AMSI test, cmd.exe spawning |
| 4 | **Persistence** | TA0003 | T1547.001, T1053.005 | Registry Run key (auto-removed), Scheduled task (auto-removed) |
| 5 | **Privilege Escalation** | TA0004 | T1134, T1548.002 | Token privilege query, UAC configuration check |
| 6 | **Defense Evasion** | TA0005 | T1562.001, T1027, T1140 | Defender status query, double extension file, certutil encode/decode |
| 7 | **Credential Access** | TA0006 | T1003.001, T1555, T1552.001 | LSASS process query, Credential Manager listing, password file search |
| 8 | **Discovery** | TA0007 | T1082, T1069.001 | Rapid system enumeration (9 commands), local group listing |
| 9 | **Lateral Movement** | TA0008 | T1021.006, T1021.002 | WinRM test to localhost, SMB share enumeration |
| 10 | **Collection** | TA0009 | T1560.001, T1074.001 | File staging, ZIP archive creation |
| 11 | **Command & Control** | TA0011 | T1071.001, T1132.001 | HTTP beacons to RFC 5737 test IPs, Base64 C2 payload |
| 12 | **Exfiltration** | TA0010 | T1048.003, T1041 | DNS tunneling to example.com, HTTP POST to test IP |

## Prerequisites

- **Windows 11** with Microsoft Defender for Endpoint (MDE) onboarded
- **PowerShell 5.1+** (built into Windows 11)
- **Administrator** recommended (some alerts require elevation)
- MDE must be in **Active mode** (not passive)

## Usage

### Run all phases interactively (recommended for demos)

```powershell
.\defender-alert-simulation.ps1
```

### Run a specific kill chain phase

```powershell
.\defender-alert-simulation.ps1 -Phase Execution
.\defender-alert-simulation.ps1 -Phase CredentialAccess
.\defender-alert-simulation.ps1 -Phase Persistence
```

### Non-interactive mode (no pauses)

```powershell
.\defender-alert-simulation.ps1 -NoPause
```

### Keep test artifacts for inspection

```powershell
.\defender-alert-simulation.ps1 -SkipCleanup
```

Available `-Phase` values:
`Reconnaissance`, `InitialAccess`, `Execution`, `Persistence`, `PrivilegeEscalation`, `DefenseEvasion`, `CredentialAccess`, `Discovery`, `LateralMovement`, `Collection`, `CommandAndControl`, `Exfiltration`

## Safety Guarantees

| Concern | Safety Measure |
|---------|---------------|
| **Malware** | No malware is used. EICAR is the industry-standard AV test file (not malicious). |
| **Persistence** | Registry keys and scheduled tasks are created and **immediately removed**. |
| **Network** | All outbound connections use RFC 5737 (203.0.113.0/24) and RFC 2606 (example.com) — documentation-reserved addresses that don't route. |
| **Credentials** | LSASS is queried read-only (PID/memory info). No credential dump is performed. No real passwords are accessed. |
| **Files** | All test files are created in `%USERPROFILE%\MDE-Demo-Test\` and auto-cleaned. |
| **System changes** | No system settings are modified. All queries are read-only. |

## Where to See Alerts

After running the script, alerts typically appear within **5–30 minutes**:

1. **Microsoft Defender Security Center**: https://security.microsoft.com
   - Navigate to **Incidents & Alerts → Alerts**
   - Filter by machine name

2. **Microsoft Sentinel** (if connected):
   - `SecurityAlert` table
   - `SecurityIncident` table
   - `DeviceEvents` / `DeviceProcessEvents` tables

3. **Advanced Hunting** (KQL):
   ```kql
   DeviceProcessEvents
   | where DeviceName == "<your-machine>"
   | where Timestamp > ago(1h)
   | where FileName in ("powershell.exe", "cmd.exe", "certutil.exe", "nslookup.exe")
   | project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
   | order by Timestamp desc
   ```

## Educational Notes

### What is a Kill Chain?

The **Cyber Kill Chain** (Lockheed Martin, 2011) describes the stages of a cyberattack. MITRE ATT&CK extends this into a comprehensive matrix of **Tactics** (the "why") and **Techniques** (the "how").

### How Defender Detects These

| Detection Method | Techniques Caught |
|-----------------|-------------------|
| **Signature-based** | EICAR test file (Phase 2) |
| **Behavioral analysis** | Encoded PowerShell, rapid enumeration, process chains |
| **AMSI** | Script content inspection (Phase 3) |
| **Heuristic rules** | Registry Run key creation, certutil abuse (LOLBin) |
| **Network monitoring** | Outbound beacons, DNS tunneling patterns |
| **Cloud-based ML** | Aggregated suspicious behavior across phases |

### Key ATT&CK Concepts

- **Tactic**: The adversary's goal (e.g., TA0003 = Persistence)
- **Technique**: How the goal is achieved (e.g., T1547.001 = Registry Run Keys)
- **LOLBin**: "Living Off the Land Binary" — legitimate OS tools abused by attackers (e.g., certutil.exe, powershell.exe)

## References

- [Microsoft MDE Detection Test](https://learn.microsoft.com/en-us/defender-endpoint/run-detection-test)
- [EICAR Test File](https://www.eicar.org/download-anti-malware-testfile/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
