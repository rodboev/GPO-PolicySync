# Sync-PolicyToRegistryPol.ps1
# Syncs current HKLM/HKCU SOFTWARE\Policies registry values back into local registry.pol,
# while preserving existing special registry.pol directives (**DeleteValues, **Del.<name>, etc.).
# Scope:
#   - Machine: HKLM\SOFTWARE\Policies   -> %SystemRoot%\System32\GroupPolicy\Machine\registry.pol
#   - User:    HKCU\SOFTWARE\Policies   -> %SystemRoot%\System32\GroupPolicy\User\registry.pol
#
# Notes:
#   - This is a forward materialization of current registry-backed policy values.
#   - Existing special directives already present in registry.pol are preserved.
#   - Ordinary existing entries under SOFTWARE\Policies are replaced to match the live registry.
#   - HKLM/HKCU roots are NOT written into registry.pol keys.
#
# Example:
#   .\Sync-PolicyToRegistryPol.ps1 -Machine -User -Backup -RefreshPolicy
#
# Default:
#   If neither -Machine nor -User is specified, -Machine -User -RefreshPolicy is assumed.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Machine,
    [switch]$User,
    [switch]$Backup = $true,
    [switch]$RefreshPolicy,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# registry.pol format constants
$script:PolSignature = 0x67655250   # 'PReg' little-endian
$script:PolVersion   = 1
$script:Unicode      = [System.Text.Encoding]::Unicode

# Supported registry.pol value types per MS-GPREG
$script:RegistryTypeMap = @{
    String       = 0x00000001  # REG_SZ
    ExpandString = 0x00000002  # REG_EXPAND_SZ
    Binary       = 0x00000003  # REG_BINARY
    DWord        = 0x00000004  # REG_DWORD
    MultiString  = 0x00000007  # REG_MULTI_SZ
    QWord        = 0x0000000B  # REG_QWORD
}

$script:TypeNameMap = @{
    [uint32]0x00000001 = 'REG_SZ'
    [uint32]0x00000002 = 'REG_EXPAND_SZ'
    [uint32]0x00000003 = 'REG_BINARY'
    [uint32]0x00000004 = 'REG_DWORD'
    [uint32]0x00000007 = 'REG_MULTI_SZ'
    [uint32]0x0000000B = 'REG_QWORD'
}

function Test-IsSpecialPolicyValueName {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    return $ValueName.StartsWith('**', [System.StringComparison]::Ordinal)
}

function Test-IsSoftwarePoliciesPath {
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath
    )

    return $KeyPath.Equals('SOFTWARE\Policies', [System.StringComparison]::OrdinalIgnoreCase) -or
           $KeyPath.StartsWith('SOFTWARE\Policies\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PolFilePath {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Machine','User')]
        [string]$Scope
    )

    $base = Join-Path $env:SystemRoot 'System32\GroupPolicy'
    if ($Scope -eq 'Machine') {
        return (Join-Path $base 'Machine\registry.pol')
    } else {
        return (Join-Path $base 'User\registry.pol')
    }
}

function Get-GptIniPath {
    return (Join-Path $env:SystemRoot 'System32\GroupPolicy\gpt.ini')
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        [void](New-Item -ItemType Directory -Path $dir -Force)
    }
}

function Backup-FileIfPresent {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupPath = '{0}.{1}.bak' -f $Path, $timestamp
    Copy-Item -LiteralPath $Path -Destination $backupPath -Force
    return $backupPath
}

function Read-Utf16NullTerminatedString {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,
        [Parameter(Mandatory)]
        [ref]$Offset
    )

    $start = $Offset.Value
    $len   = $Bytes.Length

    while ($true) {
        if ($Offset.Value + 1 -ge $len) {
            throw "Unexpected end of file while reading UTF-16LE null-terminated string."
        }

        if ($Bytes[$Offset.Value] -eq 0 -and $Bytes[$Offset.Value + 1] -eq 0) {
            $count = $Offset.Value - $start
            $value = if ($count -gt 0) {
                $script:Unicode.GetString($Bytes, $start, $count)
            } else {
                ''
            }

            $Offset.Value += 2
            return $value
        }

        $Offset.Value += 2
    }
}

function Read-UInt32Le {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,
        [Parameter(Mandatory)]
        [ref]$Offset
    )

    if ($Offset.Value + 4 -gt $Bytes.Length) {
        throw "Unexpected end of file while reading UInt32."
    }

    $value = [BitConverter]::ToUInt32($Bytes, $Offset.Value)
    $Offset.Value += 4
    return $value
}

function Expect-Utf16Char {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,
        [Parameter(Mandatory)]
        [ref]$Offset,
        [Parameter(Mandatory)]
        [char]$Expected
    )

    if ($Offset.Value + 2 -gt $Bytes.Length) {
        throw "Unexpected end of file while expecting character '$Expected'."
    }

    $actual = [BitConverter]::ToChar($Bytes, $Offset.Value)
    if ($actual -ne $Expected) {
        throw ("Invalid registry.pol format at offset {0}: expected '{1}', found '{2}'." -f $Offset.Value, $Expected, $actual)
    }

    $Offset.Value += 2
}

function Parse-RegistryPol {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 8) {
        throw "registry.pol is too short: $Path"
    }

    $offset = 0
    $signature = Read-UInt32Le -Bytes $bytes -Offset ([ref]$offset)
    $version   = Read-UInt32Le -Bytes $bytes -Offset ([ref]$offset)

    if ($signature -ne $script:PolSignature) {
        throw ("Invalid registry.pol signature in {0}. Expected 0x{1:X8}, found 0x{2:X8}." -f $Path, $script:PolSignature, $signature)
    }

    if ($version -ne $script:PolVersion) {
        throw ("Unsupported registry.pol version in {0}. Expected {1}, found {2}." -f $Path, $script:PolVersion, $version)
    }

    $entries = New-Object System.Collections.Generic.List[object]

    while ($offset -lt $bytes.Length) {
        Expect-Utf16Char -Bytes $bytes -Offset ([ref]$offset) -Expected '['

        $keyPath = Read-Utf16NullTerminatedString -Bytes $bytes -Offset ([ref]$offset)
        Expect-Utf16Char -Bytes $bytes -Offset ([ref]$offset) -Expected ';'

        $valueName = Read-Utf16NullTerminatedString -Bytes $bytes -Offset ([ref]$offset)
        Expect-Utf16Char -Bytes $bytes -Offset ([ref]$offset) -Expected ';'

        $type = Read-UInt32Le -Bytes $bytes -Offset ([ref]$offset)
        Expect-Utf16Char -Bytes $bytes -Offset ([ref]$offset) -Expected ';'

        $size = Read-UInt32Le -Bytes $bytes -Offset ([ref]$offset)
        Expect-Utf16Char -Bytes $bytes -Offset ([ref]$offset) -Expected ';'

        if ($offset + $size -gt $bytes.Length) {
            throw ("Invalid registry.pol size at offset {0}: data overruns file." -f $offset)
        }

        $data = New-Object byte[] $size
        if ($size -gt 0) {
            [Array]::Copy($bytes, $offset, $data, 0, $size)
        }
        $offset += $size

        Expect-Utf16Char -Bytes $bytes -Offset ([ref]$offset) -Expected ']'

        $entries.Add([pscustomobject]@{
            KeyPath      = $keyPath
            ValueName    = $valueName
            Type         = [uint32]$type
            Data         = $data
            IsSpecial    = (Test-IsSpecialPolicyValueName -ValueName $valueName)
            MatchKey     = ('{0}|{1}' -f $keyPath.ToUpperInvariant(), $valueName.ToUpperInvariant())
        })
    }

    return $entries.ToArray()
}

function Get-RegistryValueDataBytes {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryValueKind]$Kind,
        [Parameter()]
        $Value
    )

    switch ($Kind) {
        ([Microsoft.Win32.RegistryValueKind]::String) {
            return $script:Unicode.GetBytes(([string]$Value) + [char]0)
        }

        ([Microsoft.Win32.RegistryValueKind]::ExpandString) {
            return $script:Unicode.GetBytes(([string]$Value) + [char]0)
        }

        ([Microsoft.Win32.RegistryValueKind]::Binary) {
            if ($null -eq $Value) { return ,([byte[]]@()) }
            return ,([byte[]]$Value)
        }

        ([Microsoft.Win32.RegistryValueKind]::DWord) {
            return [BitConverter]::GetBytes([int32]$Value)
        }


        ([Microsoft.Win32.RegistryValueKind]::QWord) {
            return [BitConverter]::GetBytes([int64]$Value)
        }

        ([Microsoft.Win32.RegistryValueKind]::MultiString) {
            $strings = @()
            if ($null -ne $Value) {
                $strings = [string[]]$Value
            }

            if ($strings.Count -eq 0) {
                return ,([byte[]](0,0,0,0))
            }

            $joined = ($strings -join [char]0) + [char]0 + [char]0
            return ,($script:Unicode.GetBytes($joined))
        }

        default {
            throw "Unsupported registry value kind for registry.pol: $Kind"
        }
    }
}

function Get-RegistryValueTypeId {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryValueKind]$Kind
    )

    $name = $Kind.ToString()
    if (-not $script:RegistryTypeMap.ContainsKey($name)) {
        throw "Unsupported registry value kind for registry.pol: $Kind"
    }

    return [uint32]$script:RegistryTypeMap[$name]
}

function New-PolicyEntryFromLiveRegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName,
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryValueKind]$ValueKind,
        [Parameter()]
        $ValueData
    )

    return [pscustomobject]@{
        KeyPath   = $KeyPath
        ValueName = $ValueName
        Type      = (Get-RegistryValueTypeId -Kind $ValueKind)
        Data      = (Get-RegistryValueDataBytes -Kind $ValueKind -Value $ValueData)
        IsSpecial = $false
        MatchKey  = ('{0}|{1}' -f $KeyPath.ToUpperInvariant(), $ValueName.ToUpperInvariant())
    }
}

function Enumerate-PolicyRegistryEntries {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Machine','User')]
        [string]$Scope
    )

    $rootHive = if ($Scope -eq 'Machine') {
        [Microsoft.Win32.Registry]::LocalMachine
    }
    else {
        [Microsoft.Win32.Registry]::CurrentUser
    }

    $basePath = 'SOFTWARE\Policies'

    try {
        $baseKey = $rootHive.OpenSubKey($basePath, $false)
    }
    catch {
        Write-Warning ("Skipping inaccessible base key: {0}\{1} ({2})" -f $Scope, $basePath, $_.Exception.Message)
        return @()
    }

    if ($null -eq $baseKey) {
        return @()
    }

    $results = New-Object System.Collections.Generic.List[object]
    $stack   = New-Object System.Collections.Generic.Stack[object]
    $stack.Push([pscustomobject]@{
        Key  = $baseKey
        Path = $basePath
    })

    try {
        while ($stack.Count -gt 0) {
            $frame = $stack.Pop()
            $key   = $frame.Key
            $path  = $frame.Path

            try {
                $valueNames = $key.GetValueNames()
            }
            catch {
                Write-Warning ("Skipping unreadable values in key: {0} ({1})" -f $path, $_.Exception.Message)
                $valueNames = @()
            }

            foreach ($valueName in $valueNames) {
                try {
                    $kind = $key.GetValueKind($valueName)
                }
                catch {
                    Write-Warning ("Skipping unreadable value kind: {0}\{1} ({2})" -f $path, $valueName, $_.Exception.Message)
                    continue
                }

                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::Unknown -or
                    $kind -eq [Microsoft.Win32.RegistryValueKind]::None) {
                    Write-Warning ("Skipping unsupported value kind {0}: {1}\{2}" -f $kind, $path, $valueName)
                    continue
                }

                try {
                    $data = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                }
                catch {
                    Write-Warning ("Skipping unreadable value data: {0}\{1} ({2})" -f $path, $valueName, $_.Exception.Message)
                    continue
                }

                $results.Add(
                    (New-PolicyEntryFromLiveRegistryValue -KeyPath $path -ValueName $valueName -ValueKind $kind -ValueData $data)
                )
            }

            try {
                $subKeyNames = $key.GetSubKeyNames()
            }
            catch {
                Write-Warning ("Skipping unreadable subkey list: {0} ({1})" -f $path, $_.Exception.Message)
                $subKeyNames = @()
            }

            foreach ($subKeyName in $subKeyNames) {
                try {
                    $subKey = $key.OpenSubKey($subKeyName, $false)
                }
                catch {
                    Write-Warning ("Skipping inaccessible subkey: {0}\{1} ({2})" -f $path, $subKeyName, $_.Exception.Message)
                    continue
                }

                if ($null -ne $subKey) {
                    $stack.Push([pscustomobject]@{
                        Key  = $subKey
                        Path = ($path + '\' + $subKeyName)
                    })
                }
            }
        }
    }
    finally {
        $baseKey.Dispose()
    }

    return @($results.ToArray())
}

function Write-RegistryPol {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [object[]]$Entries
    )

    Ensure-Directory -Path $Path

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $bw = New-Object System.IO.BinaryWriter($fs, $script:Unicode, $true)

        $bw.Write([uint32]$script:PolSignature)
        $bw.Write([uint32]$script:PolVersion)

        foreach ($entry in $Entries) {
            $bw.Write([char]'[')
            $bw.Write($script:Unicode.GetBytes($entry.KeyPath))
            $bw.Write([char]0)
            $bw.Write([char]';')

            $bw.Write($script:Unicode.GetBytes([string]$entry.ValueName))
            $bw.Write([char]0)
            $bw.Write([char]';')

            $bw.Write([uint32]$entry.Type)
            $bw.Write([char]';')

            $data = [byte[]]$entry.Data
            $bw.Write([uint32]$data.Length)
            $bw.Write([char]';')

            if ($data.Length -gt 0) {
                $bw.Write($data)
            }

            $bw.Write([char]']')
        }

        $bw.Flush()
    }
    finally {
        $fs.Dispose()
    }
}

function Update-GptIniVersion {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Machine','User')]
        [string[]]$Scopes
    )

    $gptIniPath = Get-GptIniPath
    Ensure-Directory -Path $gptIniPath

    $gptEncoding = [System.Text.Encoding]::ASCII
    $content = if (Test-Path -LiteralPath $gptIniPath) {
        $rawBytes = [System.IO.File]::ReadAllBytes($gptIniPath)
        if ($rawBytes.Length -ge 2 -and $rawBytes[0] -eq 0xFF -and $rawBytes[1] -eq 0xFE) {
            $gptEncoding = [System.Text.Encoding]::Unicode
            [System.Text.Encoding]::Unicode.GetString($rawBytes, 2, $rawBytes.Length - 2)
        } elseif ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF) {
            $gptEncoding = [System.Text.Encoding]::UTF8
            [System.Text.Encoding]::UTF8.GetString($rawBytes, 3, $rawBytes.Length - 3)
        } else {
            [System.Text.Encoding]::ASCII.GetString($rawBytes)
        }
    } else {
        "[General]`r`nVersion=0`r`n"
    }

    [uint32]$version = 0
    $generalBlock = [regex]::Match($content, '(?ims)\[\s*General\s*\][^\[]*')
    if ($generalBlock.Success) {
        $m = [regex]::Match($generalBlock.Value, '(?im)^\s*Version\s*=\s*(\d+)\s*$')
        if ($m.Success) {
            $version = [uint32]$m.Groups[1].Value
        }
    }

    [uint32]$machineVersion = $version -band 0x0000FFFF
    [uint32]$userVersion    = ($version -shr 16) -band 0x0000FFFF

    foreach ($scope in $Scopes) {
        if ($scope -eq 'Machine') {
            $machineVersion = ($machineVersion + 1) -band 0x0000FFFF
        }
        elseif ($scope -eq 'User') {
            $userVersion = ($userVersion + 1) -band 0x0000FFFF
        }
    }

    [uint32]$newVersion = (($userVersion -band 0xFFFF) -shl 16) -bor ($machineVersion -band 0xFFFF)

    $blockRx = [regex]::new('(?ims)(\[\s*General\s*\][^\[]*)');
    $blockMatch = $blockRx.Match($content)

    if ($blockMatch.Success) {
        $block = $blockMatch.Value
        $versionRx = [regex]::new('(?im)^(\s*Version\s*=\s*)\d+\s*$')
        if ($versionRx.IsMatch($block)) {
            $newBlock = $versionRx.Replace($block, "`${1}$newVersion", 1)
        } else {
            $newBlock = $block.TrimEnd() + "`r`nVersion=$newVersion`r`n"
        }
        $newContent = $content.Substring(0, $blockMatch.Index) + $newBlock + $content.Substring($blockMatch.Index + $blockMatch.Length)
    } else {
        $newContent = "[General]`r`nVersion=$newVersion`r`n" + $content
    }

    $outBytes = $gptEncoding.GetPreamble() + $gptEncoding.GetBytes($newContent)
    [System.IO.File]::WriteAllBytes($gptIniPath, $outBytes)
}

function Format-EntryValue {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    if ($null -eq $Entry.Data) { $Entry.Data = [byte[]]@() }

    $typeName = if ($script:TypeNameMap.ContainsKey([uint32]$Entry.Type)) {
        $script:TypeNameMap[[uint32]$Entry.Type]
    } else {
        "0x{0:X8}" -f $Entry.Type
    }

    $dataPreview = switch ([uint32]$Entry.Type) {
        0x00000001 { # REG_SZ
            if ($Entry.Data.Length -ge 2) {
                $script:Unicode.GetString($Entry.Data, 0, [Math]::Max(0, $Entry.Data.Length - 2))
            } else { '' }
        }
        0x00000002 { # REG_EXPAND_SZ
            if ($Entry.Data.Length -ge 2) {
                $script:Unicode.GetString($Entry.Data, 0, [Math]::Max(0, $Entry.Data.Length - 2))
            } else { '' }
        }
        0x00000004 { # REG_DWORD
            if ($Entry.Data.Length -ge 4) { [BitConverter]::ToUInt32($Entry.Data, 0) } else { '(empty)' }
        }
        0x0000000B { # REG_QWORD
            if ($Entry.Data.Length -ge 8) { [BitConverter]::ToUInt64($Entry.Data, 0) } else { '(empty)' }
        }
        default {
            if ($Entry.Data.Length -eq 0) { '(empty)' }
            elseif ($Entry.Data.Length -le 16) { ($Entry.Data | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' }
            else { (($Entry.Data[0..15] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') + '...' }
        }
    }

    return '{0} = {1}' -f $typeName, $dataPreview
}

function Merge-PolicyEntries {
    param(
        [AllowNull()]
        [object[]]$ExistingEntries = @(),

        [AllowNull()]
        [object[]]$LiveEntries = @(),

        [string]$Scope = ''
    )

    $ExistingEntries = @($ExistingEntries)
    $LiveEntries     = @($LiveEntries)

    $liveMap = @{}
    foreach ($entry in $LiveEntries) {
        $liveMap[$entry.MatchKey] = $entry
    }

    $existingMap = @{}
    foreach ($entry in $ExistingEntries) {
        $existingMap[$entry.MatchKey] = $entry
    }

    $changes = New-Object System.Collections.Generic.List[object]
    $merged  = New-Object System.Collections.Generic.List[object]

    foreach ($entry in $ExistingEntries) {
        if (-not (Test-IsSoftwarePoliciesPath -KeyPath $entry.KeyPath)) {
            $merged.Add($entry)
            continue
        }

        if ($entry.IsSpecial) {
            $merged.Add($entry)
            $changes.Add([pscustomobject]@{
                Action    = 'Preserve'
                Scope     = $Scope
                KeyPath   = $entry.KeyPath
                ValueName = $entry.ValueName
                Detail    = '(special directive)'
            })
            continue
        }

        if (-not $liveMap.ContainsKey($entry.MatchKey)) {
            $changes.Add([pscustomobject]@{
                Action    = 'Remove'
                Scope     = $Scope
                KeyPath   = $entry.KeyPath
                ValueName = $entry.ValueName
                Detail    = Format-EntryValue -Entry $entry
            })
            continue
        }
    }

    foreach ($entry in $LiveEntries) {
        $merged.Add($entry)

        if ($existingMap.ContainsKey($entry.MatchKey)) {
            $old = $existingMap[$entry.MatchKey]
            $dataChanged = ($old.Type -ne $entry.Type) -or
                (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$old.Data, [byte[]]$entry.Data))

            if ($dataChanged) {
                $changes.Add([pscustomobject]@{
                    Action    = 'Update'
                    Scope     = $Scope
                    KeyPath   = $entry.KeyPath
                    ValueName = $entry.ValueName
                    Detail    = Format-EntryValue -Entry $entry
                })
            } else {
                $changes.Add([pscustomobject]@{
                    Action    = 'Unchanged'
                    Scope     = $Scope
                    KeyPath   = $entry.KeyPath
                    ValueName = $entry.ValueName
                    Detail    = Format-EntryValue -Entry $entry
                })
            }
        } else {
            $changes.Add([pscustomobject]@{
                Action    = 'Add'
                Scope     = $Scope
                KeyPath   = $entry.KeyPath
                ValueName = $entry.ValueName
                Detail    = Format-EntryValue -Entry $entry
            })
        }
    }

    return [pscustomobject]@{
        Merged  = @($merged.ToArray())
        Changes = @($changes.ToArray())
    }
}

function Process-Scope {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Machine','User')]
        [string]$Scope
    )

    $polPath = Get-PolFilePath -Scope $Scope

    if ($Backup -and -not $DryRun) {
        $backupPath = Backup-FileIfPresent -Path $polPath
        if ($backupPath) {
            Write-Verbose "Backed up $polPath -> $backupPath"
        }
    }

    $existingEntries = @(Parse-RegistryPol -Path $polPath)
    $liveEntries     = @(Enumerate-PolicyRegistryEntries -Scope $Scope)
    $mergeResult     = Merge-PolicyEntries -ExistingEntries $existingEntries -LiveEntries $liveEntries -Scope $Scope
    $mergedEntries   = @($mergeResult.Merged)
    $changes         = @($mergeResult.Changes)

    $added     = @($changes | Where-Object Action -eq 'Add')
    $removed   = @($changes | Where-Object Action -eq 'Remove')
    $updated   = @($changes | Where-Object Action -eq 'Update')
    $unchanged = @($changes | Where-Object Action -eq 'Unchanged')
    $preserved = @($changes | Where-Object Action -eq 'Preserve')

    Write-Host "`n=== $Scope scope ($polPath) ===" -ForegroundColor Cyan

    if ($added.Count -gt 0) {
        Write-Host "`n  Added ($($added.Count)):" -ForegroundColor Green
        foreach ($c in $added) {
            Write-Host "    + $($c.KeyPath)\$($c.ValueName)  [$($c.Detail)]" -ForegroundColor Green
        }
    }

    if ($updated.Count -gt 0) {
        Write-Host "`n  Updated ($($updated.Count)):" -ForegroundColor Yellow
        foreach ($c in $updated) {
            Write-Host "    ~ $($c.KeyPath)\$($c.ValueName)  [$($c.Detail)]" -ForegroundColor Yellow
        }
    }

    if ($removed.Count -gt 0) {
        Write-Host "`n  Removed ($($removed.Count)):" -ForegroundColor Red
        foreach ($c in $removed) {
            Write-Host "    - $($c.KeyPath)\$($c.ValueName)  [$($c.Detail)]" -ForegroundColor Red
        }
    }

    if ($preserved.Count -gt 0) {
        Write-Host "`n  Preserved special directives ($($preserved.Count)):" -ForegroundColor DarkGray
        foreach ($c in $preserved) {
            Write-Host "    * $($c.KeyPath)\$($c.ValueName)" -ForegroundColor DarkGray
        }
    }

    if ($unchanged.Count -gt 0) {
        Write-Host "`n  Unchanged: $($unchanged.Count)" -ForegroundColor DarkGray
    }

    if ($DryRun) {
        Write-Host "`n  [DRY RUN] No changes written." -ForegroundColor Magenta
    } elseif ($PSCmdlet.ShouldProcess($polPath, "Write $($mergedEntries.Count) registry.pol entries for scope $Scope")) {
        Write-RegistryPol -Path $polPath -Entries $mergedEntries
    }

    return [pscustomobject]@{
        Scope          = $Scope
        RegistryPol    = $polPath
        ExistingCount  = @($existingEntries).Count
        LiveCount      = @($liveEntries).Count
        AddedCount     = $added.Count
        UpdatedCount   = $updated.Count
        RemovedCount   = $removed.Count
        UnchangedCount = $unchanged.Count
        WrittenCount   = @($mergedEntries).Count
    }
}

# Require elevation — both Machine and User registry.pol live under a protected directory
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires elevation. Run from an Administrator PowerShell session."
}

# -DryRun activates ShouldProcess ($WhatIfPreference) so existing -WhatIf guards also fire
if ($DryRun) {
    $WhatIfPreference = $true
}

# Default scope
if (-not $Machine -and -not $User) {
    $Machine       = $true
    $User          = $true
    $RefreshPolicy = $true
}

$scopes = New-Object System.Collections.Generic.List[string]
if ($Machine) { $scopes.Add('Machine') }
if ($User)    { $scopes.Add('User') }

if ($Backup -and -not $DryRun) {
    $gptIniPath = Get-GptIniPath
    $gptBackup = Backup-FileIfPresent -Path $gptIniPath
    if ($gptBackup) {
        Write-Verbose "Backed up $gptIniPath -> $gptBackup"
    }
}

$results = foreach ($scope in $scopes) {
    Process-Scope -Scope $scope
}

if (-not $DryRun -and $PSCmdlet.ShouldProcess((Get-GptIniPath), "Increment gpt.ini version for scopes: $($scopes -join ', ')")) {
    Update-GptIniVersion -Scopes $scopes.ToArray()
} elseif ($DryRun) {
    Write-Host "`n[DRY RUN] Would increment gpt.ini version for scopes: $($scopes -join ', ')" -ForegroundColor Magenta
}

if ($RefreshPolicy -and -not $DryRun) {
    if ($Machine) {
        & gpupdate.exe /target:computer /force | Out-Host
    }
    if ($User) {
        & gpupdate.exe /target:user /force | Out-Host
    }
} elseif ($RefreshPolicy -and $DryRun) {
    Write-Host "`n[DRY RUN] Would run gpupdate.exe for scopes: $($scopes -join ', ')" -ForegroundColor Magenta
}

$results | Format-Table -AutoSize
