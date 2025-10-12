<#
- Lists ALL local users.
- Shows enabled/disabled status and profile creation time.
- Sends audit to Discord webhook.
- Then gives option to delete any accounts safely.
#>

function Send-ToDiscord {
    param([string]$WebhookUrl, [string]$MessageText)
    try {
        $payload = @{ content = $MessageText }
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body ($payload | ConvertTo-Json -Compress) -ContentType 'application/json' -ErrorAction Stop
        return $true
    } catch { Write-Warning "Failed posting to webhook: $($_.Exception.Message)"; return $false }
}

function Get-LocalUsersSafe {
    $list = @()
    try {
        if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
            foreach ($u in Get-LocalUser) {
                $list += [PSCustomObject]@{ Name=$u.Name; Enabled=$u.Enabled; SID=$u.SID.Value }
            }
        } else {
            $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
            foreach ($c in $adsi.Children) {
                if ($c.SchemaClassName -eq "User") {
                    $enabled = $true
                    try { $enabled = -not $c.AccountDisabled } catch {}
                    $list += [PSCustomObject]@{ Name=$c.Name; Enabled=$enabled; SID="" }
                }
            }
        }
    } catch { Write-Warning "Error enumerating users: $_" }
    return $list
}

function Remove-Account {
    param([string]$UserName, [switch]$RemoveProfile)
    $result = [ordered]@{ User = $UserName; Removed=$false; Method=""; ProfileRemoved=$false; Error="" }
    try {
        if (Get-Command Remove-LocalUser -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $UserName -ErrorAction Stop
            $result.Method="Remove-LocalUser"; $result.Removed=$true
        } else {
            $proc = Start-Process net -ArgumentList "user `"$UserName`" /delete" -NoNewWindow -Wait -PassThru -ErrorAction Stop
            $result.Removed = ($proc.ExitCode -eq 0); $result.Method="net user /delete"
            if (-not $result.Removed) { $result.Error = "net returned exit code $($proc.ExitCode)" }
        }
    } catch { $result.Error=$_.Exception.Message }

    if ($result.Removed -and $RemoveProfile) {
        try {
            $path = Join-Path $env:SystemDrive ("Users\$UserName")
            if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction Stop; $result.ProfileRemoved=$true }
        } catch { $result.ProfileRemoved=$false; $result.Error += " | Profile removal error: $($_.Exception.Message)" }
    }

    return $result
}

cls
Write-Host "=== Full User Audit + Removal Helper ===" -ForegroundColor Cyan

$webhook = Read-Host "Discord webhook URL (https://discord.com/api/webhooks/...)"
if (-not $webhook) { Write-Host "Webhook required. Exiting."; exit 1 }

Write-Host "Enumerating all local users..." -ForegroundColor Green
$users = Get-LocalUsersSafe

$entries=@()
foreach ($u in $users) {
    $profilePath = Join-Path $env:SystemDrive ("Users\$($u.Name)")
    $created = $null
    if (Test-Path $profilePath) { try { $created=(Get-Item $profilePath).CreationTime } catch {} }
    $ageReadable = if ($created) { "{0:N2} hours" -f ((Get-Date)-$created).TotalHours } else { "Unknown" }
    $entries += [PSCustomObject]@{ Name=$u.Name; Enabled=$u.Enabled; ProfilePath=$profilePath; ProfileCreated=$created; Age=$ageReadable }
}

$sb = New-Object System.Text.StringBuilder
$sb.AppendLine("**Full User Audit Report**") | Out-Null
$sb.AppendLine("Generated: $(Get-Date -Format o)") | Out-Null
$sb.AppendLine("") | Out-Null
$sb.AppendLine("Name | Enabled | ProfileCreated | Age (hours)") | Out-Null
$sb.AppendLine("---|---|---|---") | Out-Null
foreach ($e in $entries | Sort-Object Name) {
    $pc = if ($e.ProfileCreated) { $e.ProfileCreated } else { "Unknown" }
    $sb.AppendLine("$($e.Name) | $($e.Enabled) | $pc | $($e.Age)") | Out-Null
}
Send-ToDiscord -WebhookUrl $webhook -MessageText $sb.ToString() | Out-Null
Write-Host "Audit report sent to Discord." -ForegroundColor Green

Write-Host "`nAll local users:" -ForegroundColor Cyan
$idx=1
foreach ($e in $entries) { Write-Host "[$idx] $($e.Name) | Enabled: $($e.Enabled) | ProfileCreated: $($e.ProfileCreated) | Age: $($e.Age)"; $idx++ }

Write-Host "`nRemoval options:" -ForegroundColor Yellow
Write-Host "1) Remove ALL users (careful!)"
Write-Host "2) Select users to remove (comma-separated indexes or names)"
Write-Host "3) Cancel"
$choice=Read-Host "Choose 1,2,3"

if ($choice -eq '3' -or $choice -eq '') { Write-Host "No action taken. Exiting."; exit 0 }

$toRemove=@()
if ($choice -eq '1') { $toRemove=$entries }
elseif ($choice -eq '2') {
    $sel=Read-Host "Enter comma-separated indexes (1,3,5) or names"
    $raw=$sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    foreach ($r in $raw) {
        if ($r -as [int]) { $i=[int]$r; if ($i -ge 1 -and $i -le $entries.Count) { $toRemove += $entries[$i-1] } }
        else { $found=$entries | Where-Object { $_.Name -ieq $r }; if ($found) { $toRemove += $found } }
    }
}

if ($toRemove.Count -eq 0) { Write-Host "No valid users selected. Exiting."; exit 0 }

$confirm=Read-Host "Type YES to confirm removal of selected users (destructive!)"
if ($confirm -ne 'YES') { Write-Host "Aborted."; exit 0 }

$askProfile=Read-Host "Also remove profile folders? Y/N (default N)"
$removeProfiles = ($askProfile -and $askProfile.ToUpper() -eq 'Y')

$results=@()
foreach ($r in $toRemove) {
    Write-Host "Removing $($r.Name) ..." -NoNewline
    $res=Remove-Account -UserName $r.Name -RemoveProfile:$removeProfiles
    if ($res.Removed) { Write-Host " Removed." -ForegroundColor Green } else { Write-Host " Failed: $($res.Error)" -ForegroundColor Red }
    $results += $res
}

$sb2 = New-Object System.Text.StringBuilder
$sb2.AppendLine("**Removal Summary**") | Out-Null
$sb2.AppendLine("Generated: $(Get-Date -Format o)") | Out-Null
foreach ($s in $results) {
    $line="- $($s.User) | Removed: $($s.Removed) | Method: $($s.Method) | ProfileRemoved: $($s.ProfileRemoved)"
    if ($s.Error) { $line += " | Error: $($s.Error)" }
    $sb2.AppendLine($line) | Out-Null
}
Send-ToDiscord -WebhookUrl $webhook -MessageText $sb2.ToString() | Out-Null
Write-Host "Removal summary sent to Discord." -ForegroundColor Green

Write-Host "Done." -ForegroundColor Cyan
