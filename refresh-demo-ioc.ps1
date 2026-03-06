# ═══════════════════════════════════════════════════════════════════════════════
# refresh-demo-ioc.ps1 — Delete stale & recreate demo threat intel indicators
# ═══════════════════════════════════════════════════════════════════════════════
#
# Designed to run on a daily schedule (GitHub Actions cron, Azure Automation,
# or manually) so that the "Threat intel (24h)" button always finds demo IOCs.
#
# Steps:
#   1. List existing indicators tagged "soc-demo-data"
#   2. Delete them via the Sentinel TI REST API
#   3. Recreate the same 7 demo indicators with fresh timestamps
#
# Prerequisites:
#   - Azure CLI >= 2.60, logged in (or federated OIDC in GitHub Actions)
#   - Microsoft Sentinel Contributor role on the workspace
#
# Usage:
#   .\scripts\refresh-demo-ioc.ps1
#   .\scripts\refresh-demo-ioc.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <ws>
#
param(
    [string]$SubscriptionId = "0033cb93-1cd3-4180-8adc-2aa069f39475",
    [string]$ResourceGroup  = "Sentinel",
    [string]$WorkspaceName  = "SDLWS"
)

$ErrorActionPreference = "Stop"

$BaseUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/threatIntelligence/main"
$ApiVersion = "api-version=2024-03-01"

# ── Step 1: Delete existing demo indicators ───────────────────────────────────

Write-Host "[DELETE] Querying existing demo indicators (tag: soc-demo-data)..."

# List all indicators — the API may paginate; we loop through nextLink.
$listUrl  = "$BaseUrl/indicators?$ApiVersion&`$filter=threatIntelligenceTags/any(t: t eq 'soc-demo-data')&`$top=100"
$deleted  = 0

try {
    $response = az rest --method GET --url $listUrl -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Warning: Could not list indicators (may be first run). Skipping delete phase."
        Write-Host "  $response"
    } else {
        $data = $response | ConvertFrom-Json
        $existing = @()
        if ($data.value) { $existing += $data.value }

        # Follow nextLink if paginated
        while ($data.nextLink) {
            $response = az rest --method GET --url $data.nextLink -o json 2>&1
            $data = $response | ConvertFrom-Json
            if ($data.value) { $existing += $data.value }
        }

        Write-Host "  Found $($existing.Count) existing demo indicator(s)."

        foreach ($ind in $existing) {
            $name = $ind.name
            $deleteUrl = "https://management.azure.com$($ind.id)?$ApiVersion"
            try {
                az rest --method DELETE --url $deleteUrl -o none 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $deleted++
                    Write-Host "  [x] Deleted $name"
                } else {
                    Write-Host "  [!] Failed to delete $name"
                }
            } catch {
                Write-Host "  [!] Failed to delete $name - $_"
            }
        }
        Write-Host "  Deleted $deleted indicator(s)."
    }
} catch {
    Write-Host "  Warning: Could not query existing indicators. Continuing to create phase."
    Write-Host "  $_"
}

Write-Host ""

# ── Step 2: Create fresh indicators ──────────────────────────────────────────

$Indicators = @(
    @{
        ip          = "203.0.113.50"
        displayName = "Demo Brute Force Source - 203.0.113.50"
        description = "IP associated with Entra ID brute force attacks, TI IOC matches, and risky sign-ins in demo data"
        confidence  = 95
        tags        = @("demo", "soc-demo-data", "brute-force", "ioc-match")
    },
    @{
        ip          = "198.51.100.12"
        displayName = "Demo TI IOC Match - 198.51.100.12"
        description = "IP associated with Threat Intelligence IOC matches and risky sign-ins in demo data"
        confidence  = 90
        tags        = @("demo", "soc-demo-data", "ioc-match", "risky-signin")
    },
    @{
        ip          = "198.51.100.11"
        displayName = "Demo TI IOC Match - 198.51.100.11"
        description = "IP associated with Threat Intelligence IOC matches and risky sign-ins in demo data"
        confidence  = 90
        tags        = @("demo", "soc-demo-data", "ioc-match", "risky-signin")
    },
    @{
        ip          = "203.0.113.51"
        displayName = "Demo TI IOC Match - 203.0.113.51"
        description = "IP associated with Threat Intelligence IOC matches and risky sign-ins in demo data"
        confidence  = 90
        tags        = @("demo", "soc-demo-data", "ioc-match", "risky-signin")
    },
    @{
        ip          = "203.0.113.52"
        displayName = "Demo TI IOC Match - 203.0.113.52"
        description = "IP associated with Threat Intelligence IOC matches and risky sign-ins in demo data"
        confidence  = 90
        tags        = @("demo", "soc-demo-data", "ioc-match", "risky-signin")
    },
    @{
        ip          = "198.51.100.10"
        displayName = "Demo TI IOC Match - 198.51.100.10"
        description = "IP associated with Threat Intelligence IOC matches and risky sign-ins in demo data"
        confidence  = 85
        tags        = @("demo", "soc-demo-data", "ioc-match", "risky-signin")
    },
    @{
        ip          = "192.0.2.213"
        displayName = "Demo Risky Sign-in Source - 192.0.2.213"
        description = "IP associated with risky sign-in location alerts in demo data"
        confidence  = 80
        tags        = @("demo", "soc-demo-data", "risky-signin")
    }
)

Write-Host "[CREATE] Creating $($Indicators.Count) fresh demo indicators in workspace '$WorkspaceName'..."
Write-Host ""

$created = 0
$tmpFile = [System.IO.Path]::GetTempFileName()

foreach ($ind in $Indicators) {
    $body = @{
        kind       = "indicator"
        properties = @{
            source                 = "SOC Demo Data"
            displayName            = $ind.displayName
            description            = $ind.description
            threatTypes            = @("malicious-activity")
            pattern                = "[ipv4-addr:value = '$($ind.ip)']"
            patternType            = "ipv4-addr"
            validFrom              = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            validUntil             = (Get-Date).AddMonths(3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            confidence             = $ind.confidence
            threatIntelligenceTags = $ind.tags
        }
    } | ConvertTo-Json -Depth 5

    Set-Content -Path $tmpFile -Value $body -Encoding utf8

    try {
        $result = az rest --method POST `
            --url "$BaseUrl/createIndicator?$ApiVersion" `
            --body "@$tmpFile" `
            --query "properties.pattern" -o tsv 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] $($ind.ip)  (confidence=$($ind.confidence))"
            $created++
        } else {
            Write-Host "  [FAIL] $($ind.ip)  - $result"
        }
    } catch {
        Write-Host "  [FAIL] $($ind.ip)  - $_"
    }
}

Remove-Item $tmpFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[DONE] Deleted $deleted old, created $created / $($Indicators.Count) new indicators."
Write-Host "   Indicators take 5-15 min to appear in ThreatIntelIndicators table."
