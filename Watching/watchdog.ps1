<#
THIS SCRIPT LOGS CHANGES IN FIREWALL AND SSH AND RDP SESSIONS. THIS WILL LOG INTO A DISCORD WEBHOOK. GOD I HOPE IT WORKS!
#>

$servicesToMonitor = @("TermService","wuauserv","MSSQLSERVER")
$portsToCheck = @{ "RDP" = 3389; "SSH" = 22; "HTTP" = 80; "MySQL" = 3306 }
$checkIntervalSec = 1
$discordWebhook = Read-Host -Prompt "Enter Discord Webhook URL (required)"
if ([string]::IsNullOrWhiteSpace($discordWebhook)) { Write-Host "Webhook required. Exiting."; exit 1 }
Write-Host "Discord alerts enabled."

function Send-Discord {
    param([string]$WebhookUrl, [string]$Message)
    if ($Message.Length -le 1900) {
        try { Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body (@{content=$Message} | ConvertTo-Json) -ContentType 'application/json' } 
        catch { Write-Host "Failed sending Discord message: $_" }
    } else {
        $tmp = Join-Path $env:TEMP ("watchdog_{0}.txt" -f ([guid]::NewGuid()))
        $Message | Out-File -FilePath $tmp -Encoding UTF8
        try {
            $form = @{
                "content" = "Watchdog report attached"
                "file" = Get-Item $tmp
            }
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Form $form
        } catch { Write-Host "Failed sending file: $_" }
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Test-Port { param([string]$TargetHost,[int]$Port,[int]$TimeoutMs=800) try {$tcp=New-Object System.Net.Sockets.TcpClient;$a=$tcp.BeginConnect($TargetHost,$Port,$null,$null);$w=$a.AsyncWaitHandle.WaitOne($TimeoutMs);if($w -and $tcp.Connected){$tcp.Close();return $true}else{return $false}} catch{return $false} }

function Clone-Hashtable {
    param([hashtable]$ht)
    $newHt = @{}
    if ($ht) { $ht.GetEnumerator() | ForEach-Object { $newHt[$_.Key] = $_.Value } }
    return $newHt
}

function Get-FirewallRulesSnapshot {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
    $snap = @{}
    foreach($r in $rules) {
        $key = if($r.DisplayName) { $r.DisplayName } else { $r.Name }
        $snap[$key] = ($r | Select Name, DisplayName, Enabled, Direction, Action, Profile | ConvertTo-Json -Compress)
    }
    return $snap
}

function Build-DiffMessage {
    param($prevState,$currState,$label)
    $msg=""
    $allKeys=($prevState.Keys + $currState.Keys)|Select-Object -Unique
    foreach($k in $allKeys){
        $had=$prevState.ContainsKey($k); $has=$currState.ContainsKey($k)
        if($had -and -not $has){$msg+="ALERT [$label REMOVED]: $k`n"}
        elseif(-not $had -and $has){$msg+="ALERT [$label ADDED]: $k`n"}
        elseif($had -and $has -and $prevState[$k]-ne $currState[$k]){$msg+="ALERT [$label MODIFIED]: $k`n"}
    }
    if($msg.Trim().Length -eq 0){return $null}else{return $msg}
}

function Get-ServiceState { $h=@{}; foreach($s in $servicesToMonitor){try{$svc=Get-Service $s -ErrorAction Stop;$h[$s]=$svc.Status.ToString()}catch{$h[$s]="NotFound"}}; return $h }
function Get-PortState { $h=@{}; foreach($p in $portsToCheck.GetEnumerator()){$h[$p.Key]=if(Test-Port $p.Value -TargetHost "127.0.0.1"){"up"}else{"down"}}; return $h }
function Get-FirewallProfileState { $h=@{}; try{$fw=Get-NetFirewallProfile -Profile Domain,Public,Private -ErrorAction SilentlyContinue;foreach($f in $fw){$h[$f.Name]=if($f.Enabled){"up"}else{"off"}}} catch {}; return $h }

$seenEvents = @{}
function Get-RecentLogons {
    try {
        $startTime = (Get-Date).AddSeconds(-$checkIntervalSec)

        $events = Get-WinEvent -LogName Security -MaxEvents 5000 -ErrorAction SilentlyContinue |
                  Where-Object { $_.Id -eq 4624 -and $_.TimeCreated -ge $startTime }

        foreach ($e in $events) {
            if (-not $seenEvents.ContainsKey($e.RecordId)) {
                $seenEvents[$e.RecordId] = $true
                $acct = $e.Properties[5].Value
                $logonType = $e.Properties[8].Value

                if ($logonType -in 2,10) {
                    $msg = "ALERT [LOGIN] User '$acct' logged in at $($e.TimeCreated) (LogonType $logonType)"
                    Send-Discord -WebhookUrl $discordWebhook -Message $msg
                }

                if ($logonType -eq 10 -and $acct -ne $null -and (Get-Process -Name sshd -ErrorAction SilentlyContinue)) {
                    $msg = "ALERT [SSH LOGIN] User '$acct' connected via SSH at $($e.TimeCreated)"
                    Send-Discord -WebhookUrl $discordWebhook -Message $msg
                }
            }
        }
    } catch { Write-Host "Error reading logon events: $_" }
}

$serviceStates=Get-ServiceState
$portStates=Get-PortState
$fwProfiles=Get-FirewallProfileState
$fwRules=Get-FirewallRulesSnapshot

$initialMsg = "=== Watchdog INITIAL SNAPSHOT ===`n"
$initialMsg += "Services:`n" + ($serviceStates.GetEnumerator()|ForEach-Object{"- $($_.Key) : $($_.Value)"}|Out-String)
$initialMsg += "Ports:`n" + ($portStates.GetEnumerator()|ForEach-Object{"- $($_.Key) : $($_.Value)"}|Out-String)
$initialMsg += "Firewall Profiles:`n" + ($fwProfiles.GetEnumerator()|ForEach-Object{"- $($_.Key) : $($_.Value)"}|Out-String)
Send-Discord -WebhookUrl $discordWebhook -Message $initialMsg
Write-Host "Watchdog running. Initial snapshot sent." -ForegroundColor Green

while($true){
    Start-Sleep -Seconds $checkIntervalSec

    $prevService = Clone-Hashtable $serviceStates
    $prevPort = Clone-Hashtable $portStates
    $prevFwProfile = Clone-Hashtable $fwProfiles
    $prevFwRules = Clone-Hashtable $fwRules

    $serviceStates=Get-ServiceState
    $portStates=Get-PortState
    $fwProfiles=Get-FirewallProfileState
    $fwRules=Get-FirewallRulesSnapshot

    foreach($s in $serviceStates.Keys.Clone()){if($serviceStates[$s] -ne "Running"){try{Start-Service $s -ErrorAction Stop;$serviceStates[$s]="Running (restarted)"}catch{}}}

    foreach($p in $fwProfiles.Keys.Clone()){if($fwProfiles[$p] -eq "off"){try{Set-NetFirewallProfile -Profile $p -Enabled True -ErrorAction Stop;$fwProfiles[$p]="up (re-enabled)"}catch{}}}

    $diffs=@()
    $diffs+=Build-DiffMessage -prevState $prevService -currState $serviceStates -label "SERVICE"
    $diffs+=Build-DiffMessage -prevState $prevPort -currState $portStates -label "PORT"
    $diffs+=Build-DiffMessage -prevState $prevFwProfile -currState $fwProfiles -label "FIREWALL PROFILE"
    $diffs+=Build-DiffMessage -prevState $prevFwRules -currState $fwRules -label "FIREWALL RULE"

    $alerts = $diffs | Where-Object {$_} | Out-String
    if($alerts.Trim().Length -gt 0){Send-Discord -WebhookUrl $discordWebhook -Message $alerts}

    Get-RecentLogons
}
