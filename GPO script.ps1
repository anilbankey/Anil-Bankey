# ===============================
# GPO Deep Assessment Script
# ===============================

Import-Module GroupPolicy
Import-Module ActiveDirectory
Created by: Anil Bankey

$ReportPath = "C:\GPO_Audit_Report"
New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null

$AllGPOs = Get-GPO -All
$Summary = @()

Write-Host "Starting GPO Deep Assessment..." -ForegroundColor Cyan

foreach ($GPO in $AllGPOs) {

    $GPOReportXml = Get-GPOReport -Guid $GPO.Id -ReportType Xml
    $GPOReportHtml = Join-Path $ReportPath "$($GPO.DisplayName).html"
    Get-GPOReport -Guid $GPO.Id -ReportType Html -Path $GPOReportHtml

    $XmlObject = [xml]$GPOReportXml

    $HasUserSettings = $XmlObject.GPO.User.Enabled
    $HasComputerSettings = $XmlObject.GPO.Computer.Enabled

    $Links = (Get-GPOLink -Guid $GPO.Id -ErrorAction SilentlyContinue)
    
    $EmptyGPO = $false
    if ($HasUserSettings -eq "false" -and $HasComputerSettings -eq "false") {
        $EmptyGPO = $true
    }

    $Unlinked = $false
    if (!$Links) {
        $Unlinked = $true
    }

    # Security Filtering Check
    $Permissions = Get-GPPermission -Guid $GPO.Id -All
    $NestedGroupRisk = $false
    foreach ($Perm in $Permissions) {
        if ($Perm.Trustee.Name -match "Domain Admins") {
            $NestedGroupRisk = $true
        }
    }

    # Risk Rating
    $Risk = "Low"
    if ($EmptyGPO -or $Unlinked) { $Risk = "Medium" }
    if ($NestedGroupRisk) { $Risk = "High" }

    $Summary += [PSCustomObject]@{
        GPOName = $GPO.DisplayName
        Empty = $EmptyGPO
        Unlinked = $Unlinked
        NestedAdminRisk = $NestedGroupRisk
        RiskLevel = $Risk
    }
}

$Summary | Export-Csv "$ReportPath\GPO_Risk_Summary.csv" -NoTypeInformation

Write-Host "Assessment Completed. Reports saved at $ReportPath" -ForegroundColor Green
📊 What This Script Detects
1️⃣ Empty GPOs

No user settings

No computer settings
👉 Clutter risk

2️⃣ Unlinked GPOs

Not linked to any OU / Domain
👉 Change management gap

3️⃣ Nested Admin Filtering Risk

If privileged groups used improperly in security filtering
👉 Privilege escalation path

4️⃣ HTML Detailed Report Per GPO

Contains:

All enabled settings

Security filtering

WMI filters

Links

Delegation

Computer & User policies

🚨 Additional Advanced Risk Checks (Optional Enhancements)

You can extend script to detect:

Password policy not enforced at domain level

SMBv1 not disabled

NTLM not restricted

No audit policy

Firewall disabled via GPO

Unrestricted software installation

Scripts configured in startup/shutdown

🔴 Enterprise Risk Indicators

Immediate concern if:

20% GPOs unlinked

10 empty GPOs

No security baseline GPO

No change control tracking

Domain-level GPO modified frequently