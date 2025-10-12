<#
THIS WILL CHANGE ALL PASSWORDS ON THE MACHINE AND THEN SEND THOSE PASSWORDS TO A DISCORD WEBHOOK. REMOVE THIS FILE ONCE RAN OR ELSE RED TEAM CAN CHANGE THE PASSWORDS AGAIN BUT I GUESS IT DOESNT MATTER SINCE ITS GETTING LOGGED TO UR DISCORD ANYWAYS?

#>
param(
    [int]$PasswordLength = 16
)

$webhookPattern = '^https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+$'

do {
    $discordWebhook = Read-Host -Prompt "Enter Discord Webhook URL (required)"
    if ([string]::IsNullOrWhiteSpace($discordWebhook)) {
        Write-Host "A Discord webhook is required to run this script."
    } elseif ($discordWebhook -notmatch $webhookPattern) {
        Write-Host "The URL entered does not appear to be a valid Discord webhook. Please try again."
        $discordWebhook = $null
    }
} while ([string]::IsNullOrWhiteSpace($discordWebhook))

Write-Host "Discord webhook validated. Alerts enabled."
$useWebhook = $true

function New-RandomPassword {
    param([int]$Length=16)
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $lower = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $digits = "0123456789".ToCharArray()
    $symbols = "!@#$%^&*()-_=+[]{};:,.<>?".ToCharArray()

    $pw = @()
    $pw += $upper | Get-Random
    $pw += $lower | Get-Random
    $pw += $digits | Get-Random
    $pw += $symbols | Get-Random

    $all = $upper + $lower + $digits + $symbols
    for ($i = $pw.Count; $i -lt $Length; $i++) { $pw += $all | Get-Random }
    return -join ($pw | Get-Random -Count $pw.Count)
}

function Send-Discord {
    param([string]$msg)
    if ($useWebhook) {
        try {
            $payload = @{ content = $msg }
            Invoke-RestMethod -Uri $discordWebhook -Method Post -Body ($payload | ConvertTo-Json -Compress) -ContentType 'application/json'
        } catch {
            Write-Host "Failed to send message to Discord: $_"
        }
    }
}

$users = Get-LocalUser
Write-Host "Found $($users.Count) local users to reset passwords."

foreach ($u in $users) {
    $userName = $u.Name
    $plainPassword = New-RandomPassword -Length $PasswordLength
    $securePwd = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    try {
        Set-LocalUser -Name $userName -Password $securePwd -ErrorAction Stop
        Write-Host "SUCCESS: Changed password for $userName"

        $msg = "Password reset for user **$userName**:`n$plainPassword"
        Send-Discord $msg

    } catch {
        $err = $_.Exception.Message
        Write-Host "FAILED: Could not change password for $userName - $err"
        Send-Discord "FAILED to change password for user **$userName**. Error: $err"
    }

    $plainPassword = $null
    $securePwd = $null
    [System.GC]::Collect()
    Start-Sleep -Milliseconds 50
}

Write-Host "All users processed."
Send-Discord "Password reset completed on $(hostname) at $(Get-Date -Format s)"
