param(
    [string]$ServerUrl = "https://automation.exchange-ip.com",
    [string]$YSBaseUrl = "http://127.0.0.1:54032"
)

$ErrorActionPreference = "Stop"
$sourceAgent = Join-Path $PSScriptRoot "YSBridgeAgent.ps1"
if (-not (Test-Path -LiteralPath $sourceAgent)) { throw "YSBridgeAgent.ps1 must be beside this setup script." }
$installDir = Join-Path $env:LOCALAPPDATA "WarriorYSBridge"
$agentPath = Join-Path $installDir "YSBridgeAgent.ps1"
$configPath = Join-Path $installDir "config.json"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -LiteralPath $sourceAgent -Destination $agentPath -Force

Write-Host "Paste the one-time bridge token from the Django provision command."
$agentToken = Read-Host "Bridge token" -AsSecureString
Write-Host "Enter the YSBrowser X-API-Key. It will be encrypted for this Windows user."
$ysApiKey = Read-Host "YSBrowser API key" -AsSecureString
$config = @{
    server_url = $ServerUrl.TrimEnd("/")
    ys_base_url = $YSBaseUrl.TrimEnd("/")
    agent_token = ConvertFrom-SecureString $agentToken
    ys_api_key = ConvertFrom-SecureString $ysApiKey
}
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8

$startupDir = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startupDir "Warrior YS Bridge.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPath`""
$shortcut.WorkingDirectory = $installDir
$shortcut.Save()

Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$agentPath`"")
Write-Host "YS bridge installed and started. It will also start when you sign in."
Write-Host "Open $ServerUrl/panel/mobile-ops/ and confirm that the bridge shows Online."
