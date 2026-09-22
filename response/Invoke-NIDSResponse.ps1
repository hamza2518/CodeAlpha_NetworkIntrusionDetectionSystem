param(
    [string]$EveFile = "C:\Program Files\Suricata\log\eve.json",
    [switch]$BlockSourceIP
)

$ResponseLog = "C:\CodeAlpha_NetworkIntrusionDetectionSystem\response\incident_response.log"

if (-not (Test-Path $EveFile)) {
    Write-Error "EVE file not found: $EveFile"
    exit 1
}

$alerts = Get-Content $EveFile -ErrorAction Stop |
    ForEach-Object {
        try {
            $_ | ConvertFrom-Json
        }
        catch {
            $null
        }
    } |
    Where-Object {
        $_.event_type -eq "alert" -and
        $_.alert.signature_id -eq 1000001
    }

foreach ($event in $alerts) {

    $timestamp = $event.timestamp
    $srcIP = $event.src_ip
    $destIP = $event.dest_ip
    $signature = $event.alert.signature
    $sid = $event.alert.signature_id

    $entry = @"
[$timestamp]
SID: $sid
Alert: $signature
Source: $srcIP
Destination: $destIP
Action: Analyst review required
"@

    Add-Content -Path $ResponseLog -Value $entry

    Write-Host "ALERT DETECTED"
    Write-Host "Source      : $srcIP"
    Write-Host "Destination : $destIP"
    Write-Host "Signature   : $signature"

    if ($BlockSourceIP) {

        if ($srcIP -eq "192.168.1.8" -or $srcIP -eq "192.168.1.1") {
            Write-Warning "SAFEGUARD: refusing to block known lab/test IP $srcIP"
            continue
        }

        New-NetFirewallRule `
            -DisplayName "CodeAlpha NIDS Block $srcIP" `
            -Direction Inbound `
            -RemoteAddress $srcIP `
            -Action Block `
            -Profile Any `
            -Description "Created by CodeAlpha NIDS response workflow."

        Write-Host "Firewall block created for $srcIP"
    }
}

if ($alerts.Count -eq 0) {
    Write-Host "No matching CodeAlpha alerts found."
}
else {
    Write-Host "$($alerts.Count) matching alert(s) processed."
}
