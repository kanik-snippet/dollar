param(
    [string]$ConfigPath = "$env:LOCALAPPDATA\WarriorYSBridge\config.json",
    [string]$LogPath = "$env:LOCALAPPDATA\WarriorYSBridge\bridge.log",
    [switch]$Once
)

$ErrorActionPreference = "Stop"
$BridgeVersion = "1.0.0"
$runContinuously = -not $Once.IsPresent
function Write-BridgeLog([string]$Message) {
    try { Add-Content -LiteralPath $LogPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" -Encoding UTF8 }
    catch { }
}
$createdNew = $false
$singleInstance = [Threading.Mutex]::new($true, "Local\WarriorYSBridgeAgent", [ref]$createdNew)
if (-not $createdNew) { Write-BridgeLog "Bridge already running; duplicate process exited."; exit 0 }
Write-BridgeLog "Bridge v$BridgeVersion started (PID=$PID, continuous=$runContinuously)."

function Unprotect-Value([string]$EncryptedValue) {
    if (-not $EncryptedValue -or $EncryptedValue.Length % 2 -ne 0 -or $EncryptedValue -notmatch '^[0-9a-fA-F]+$') {
        throw "Encrypted configuration value has an invalid format."
    }
    $cipherBytes = New-Object byte[] ($EncryptedValue.Length / 2)
    for ($index = 0; $index -lt $cipherBytes.Length; $index++) {
        $cipherBytes[$index] = [Convert]::ToByte($EncryptedValue.Substring($index * 2, 2), 16)
    }
    [void][Reflection.Assembly]::LoadWithPartialName("System.Security")
    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $cipherBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [Text.Encoding]::Unicode.GetString($plainBytes)
}

function Invoke-JsonRequest {
    param([string]$Url, [string]$Method, [hashtable]$Headers, $Body = $null)
    $params = @{ Uri = $Url; Method = $Method; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 45 }
    if ($null -ne $Body) {
        $params.ContentType = "application/json"
        $params.Body = ($Body | ConvertTo-Json -Depth 12 -Compress)
    }
    return Invoke-RestMethod @params
}

function Get-FirstValue($Object, [string[]]$Names) {
    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value -and "$($property.Value)".Trim()) {
            return "$($property.Value)".Trim()
        }
    }
    return ""
}

function Get-ResponseRows($Response) {
    if ($null -eq $Response) { return @() }
    if ($Response -is [System.Array]) { return @($Response) }
    foreach ($name in @("records", "rows", "list", "items", "environments")) {
        $property = $Response.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) { return @($property.Value) }
    }
    $data = $Response.PSObject.Properties["data"]
    if ($null -ne $data -and $null -ne $data.Value) { return @(Get-ResponseRows $data.Value) }
    return @()
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    Write-BridgeLog "Configuration file is missing at the expected per-user path."
    throw "Bridge config not found. Run Setup-YSBridge.ps1 first."
}
try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $serverUrl = "$($config.server_url)".TrimEnd("/")
    $ysBaseUrl = "$($config.ys_base_url)".TrimEnd("/")
    $agentToken = Unprotect-Value "$($config.agent_token)"
    $ysApiKey = Unprotect-Value "$($config.ys_api_key)"
    Write-BridgeLog "Per-user configuration decrypted."
} catch {
    Write-BridgeLog "Configuration could not be loaded: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    throw
}
$bridgeHeaders = @{ Authorization = "Bearer $agentToken"; "X-Bridge-Version" = $BridgeVersion }
$ysHeaders = @{ "X-API-Key" = $ysApiKey }

function Invoke-YS([string]$Path, [string]$Method = "GET", $Body = $null) {
    $response = Invoke-JsonRequest -Url ($ysBaseUrl + $Path) -Method $Method -Headers $ysHeaders -Body $Body
    $successProperty = $response.PSObject.Properties["success"]
    if ($null -ne $successProperty -and $successProperty.Value -eq $false) {
        $message = Get-FirstValue $response @("msg", "message", "error")
        throw "YSBrowser API rejected the request: $message"
    }
    $codeProperty = $response.PSObject.Properties["code"]
    if ($null -ne $codeProperty -and "$($codeProperty.Value)" -notin @("0", "200", "success", "SUCCESS")) {
        $message = Get-FirstValue $response @("msg", "message", "error")
        throw "YSBrowser API code $($codeProperty.Value): $message"
    }
    return $response
}

function Get-AllEnvironments {
    $all = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $pageSize = 100
    for ($page = 1; $page -le 200; $page++) {
        $response = Invoke-YS "/api/environments/list?pageNum=$page&pageSize=$pageSize"
        $rows = @(Get-ResponseRows $response)
        if ($rows.Count -eq 0) { break }
        $newOnPage = 0
        foreach ($row in $rows) {
            $browserId = Get-FirstValue $row @("browserId", "browser_id", "id")
            if ($browserId -and $seen.Add($browserId)) { $all.Add($row); $newOnPage++ }
        }
        if ($rows.Count -lt $pageSize -or $newOnPage -eq 0) { break }
    }
    return @($all)
}

function Remove-OfficeEnvironments($Payload) {
    $groupSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($groupId in @($Payload.group_ids)) { [void]$groupSet.Add("$groupId".Trim()) }
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($environment in @(Get-AllEnvironments)) {
        $groupId = Get-FirstValue $environment @("groupId", "group_id", "browserGroupId", "browser_group_id")
        if (-not $groupSet.Contains($groupId)) { continue }
        $browserId = Get-FirstValue $environment @("browserId", "browser_id", "id")
        $profileId = Get-FirstValue $environment @("profileId", "profile_id")
        if ($browserId -and $profileId) {
            $matched.Add([pscustomobject]@{ browserId = $browserId; profileId = $profileId })
        }
    }
    $closed = 0
    foreach ($item in $matched) {
        try { [void](Invoke-YS "/api/browser/close/$($item.browserId)" "POST"); $closed++ }
        catch { Start-Sleep -Milliseconds 200 }
    }
    $deleted = 0
    for ($offset = 0; $offset -lt $matched.Count; $offset += 100) {
        $end = [Math]::Min($offset + 99, $matched.Count - 1)
        $batch = @($matched[$offset..$end])
        $body = @{
            browserIds = @($batch | ForEach-Object { $_.browserId })
            browserList = @($batch | ForEach-Object { @{ browserId = $_.browserId; profileId = $_.profileId } })
            deleteLocalCache = [bool]$Payload.delete_local_cache
        }
        [void](Invoke-YS "/api/environments/del" "DELETE" $body)
        $deleted += $batch.Count
    }
    return @{ groups = $groupSet.Count; matched = $matched.Count; closed = $closed; deleted = $deleted }
}

function Get-WhitelistIps {
    $values = New-Object System.Collections.Generic.HashSet[string]
    $response = Invoke-YS "/api/ipWhite/list?pageNum=1&pageSize=1000"
    foreach ($row in @(Get-ResponseRows $response)) {
        $value = Get-FirstValue $row @("ipAddress", "ip_address", "ip")
        if ($value) { [void]$values.Add($value) }
    }
    return ,$values
}

function Set-WhitelistIp([string]$IPv4, [bool]$ShouldExist) {
    $before = Get-WhitelistIps
    if ($ShouldExist -and $before.Contains($IPv4)) {
        return @{ ipv4 = $IPv4; operation = "already_present"; verified = $true }
    }
    if (-not $ShouldExist -and -not $before.Contains($IPv4)) {
        return @{ ipv4 = $IPv4; operation = "already_absent"; verified = $true }
    }
    if ($ShouldExist) { [void](Invoke-YS "/api/ipWhite/add" "POST" @{ ipAddress = $IPv4 }) }
    else { [void](Invoke-YS "/api/ipWhite/del" "DELETE" @{ ipAddress = $IPv4 }) }
    $after = Get-WhitelistIps
    $verified = $after.Contains($IPv4) -eq $ShouldExist
    if (-not $verified) { throw "YSBrowser whitelist verification failed for $IPv4" }
    return @{ ipv4 = $IPv4; operation = $(if ($ShouldExist) { "added" } else { "removed" }); verified = $true }
}

function Invoke-BridgeCommand($Command) {
    [void](Invoke-YS "/api/status")
    switch ("$($Command.action)") {
        "delete_environments" { return Remove-OfficeEnvironments $Command.payload }
        "whitelist_add" {
            return Set-WhitelistIp "$($Command.payload.ipv4)" $true
        }
        "whitelist_remove" {
            return Set-WhitelistIp "$($Command.payload.ipv4)" $false
        }
        default { throw "Unsupported bridge action: $($Command.action)" }
    }
}

$announcedOnline = $false
do {
    try {
        $poll = Invoke-JsonRequest -Url "$serverUrl/api/v1/ys-bridge/poll/" -Method "POST" -Headers $bridgeHeaders -Body @{}
        if (-not $announcedOnline) { Write-BridgeLog "Server connection authenticated."; $announcedOnline = $true }
        if ($null -ne $poll.command) {
            Write-BridgeLog "Executing command $($poll.command.id) ($($poll.command.action))."
            $completion = @{ success = $false; result = @{}; error = "" }
            try {
                $completion.result = Invoke-BridgeCommand $poll.command
                $completion.success = $true
            } catch {
                $completion.error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
            }
            [void](Invoke-JsonRequest -Url "$serverUrl/api/v1/ys-bridge/commands/$($poll.command.id)/complete/" -Method "POST" -Headers $bridgeHeaders -Body $completion)
            Write-BridgeLog "Command $($poll.command.id) reported (success=$($completion.success))."
        }
    } catch {
        if ($Once) { throw }
        Write-BridgeLog "Poll failed: $($_.Exception.GetType().Name): $($_.Exception.Message)"
        $announcedOnline = $false
        Start-Sleep -Seconds 10
    }
    if ($runContinuously) { Start-Sleep -Seconds 4 }
} while ($runContinuously)
Write-BridgeLog "Bridge stopped."
