# GPO-PolicySync

A PowerShell script that syncs registry-based policy values back into the local Group Policy store (`registry.pol` files).

## Why

A lot of Windows hardening and privacy tools (privacy.sexy, Chris Titus WinUtil, etc.) write policy settings directly to the registry under `HKLM\SOFTWARE\Policies` or `HKCU\SOFTWARE\Policies`. This works... until it doesn't:

- Those settings **don't show up in `gpedit.msc`**, so you can't see what's actually configured
- Running `gpupdate` **overwrites them**, because the Group Policy engine applies whatever's in `registry.pol`, not the live registry
- You **can't back them up with LGPO.exe**, because LGPO reads from the `.pol` files, not the registry hive
- They're basically invisible and fragile

The root cause is that Windows Group Policy is a one-way street: `registry.pol` -> registry. There's no built-in way to go the other direction.

## How

`Sync-PolicyToRegistryPol.ps1` reads the live registry under `SOFTWARE\Policies` and merges those values back into the local Machine and User policy stores (`System32\GroupPolicy\Machine\registry.pol` and `User\registry.pol`). It does a proper diff/merge, not a blind overwrite:

- **Adds** entries that exist in the registry but not in `registry.pol`
- **Updates** entries where the registry value has changed
- **Removes** entries from `registry.pol` that no longer exist in the registry
- **Preserves** special Group Policy directives (`**DeleteValues`, `**Del.*`, etc.)
- **Preserves** non-policy entries (anything outside `SOFTWARE\Policies`)
- Bumps the `gpt.ini` version number so the Group Policy engine recognizes the change

After syncing, your policy settings are visible in the Group Policy Editor, survive `gpupdate`, and can be exported with `LGPO.exe /b` for backup or deployment to other machines.

## Usage

Run from an elevated (Administrator) PowerShell prompt:

```powershell
# Sync both Machine and User policies, then refresh Group Policy (default)
.\Sync-PolicyToRegistryPol.ps1

# Machine policies only
.\Sync-PolicyToRegistryPol.ps1 -Machine

# User policies only
.\Sync-PolicyToRegistryPol.ps1 -User

# Preview what would change without writing anything
.\Sync-PolicyToRegistryPol.ps1 -DryRun

# Skip the automatic gpupdate at the end
.\Sync-PolicyToRegistryPol.ps1 -Machine -User
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-Machine` | Sync `HKLM\SOFTWARE\Policies` to `Machine\registry.pol` |
| `-User` | Sync `HKCU\SOFTWARE\Policies` to `User\registry.pol` |
| `-DryRun` | Show what would change without writing any files |
| `-Backup` | Back up existing `.pol` and `gpt.ini` files before writing (on by default) |
| `-RefreshPolicy` | Run `gpupdate /force` after syncing |

If you don't pass `-Machine` or `-User`, the script defaults to both plus `-RefreshPolicy`.

### Output

The script shows color-coded output for each scope:

- **Green** (+) = new entries being added to `registry.pol`
- **Blue** (~) = entries being updated
- **Red** (-) = stale entries being removed
- **Gray** (*) = preserved special directives
- **Gray** = count of unchanged entries

DryRun mode shows the same breakdown in magenta without writing anything.

## The Bigger Picture

This fills a specific gap in the Windows policy toolchain:

```
┌─────────────────────────────────────────────┐
│  1. Hardening tool writes to registry       │
│     (privacy.sexy, WinUtil, etc.)           │
│                                             │
│  2. Sync-PolicyToRegistryPol.ps1            │  <-- this script
│     merges registry -> registry.pol         │
│                                             │
│  3. gpedit.msc now shows everything         │
│     gpupdate no longer wipes your settings  │
│                                             │
│  4. LGPO.exe /b can back up the full GPO    │
│     LGPO.exe /g can restore it anywhere     │
└─────────────────────────────────────────────┘
```

Without step 2, the settings from step 1 are invisible to everything that reads Group Policy files, and they get wiped on the next policy refresh.

## Technical Details

The script works directly with the [MS-GPREG binary format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/) (the PReg format used by `registry.pol` files). It doesn't depend on any external modules or tools.

The merge treats the live registry as the source of truth for policy entries under `SOFTWARE\Policies`:

1. **Non-policy entries** in the existing `.pol` file (anything outside `SOFTWARE\Policies`) are kept as-is
2. **Special GP directives** (`**DeleteValues`, `**Del.*`, etc.) are always preserved
3. **Policy entries that exist in the registry but not in `.pol`** are added
4. **Policy entries that exist in both** but differ in type or data are overwritten with the registry value
5. **Policy entries that exist in `.pol` but not in the registry** are removed (stale entries from policies that were unconfigured or deleted)

Supported registry value types: `REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_MULTI_SZ`, `REG_QWORD`.

The `gpt.ini` version update handles encoding detection (ASCII, UTF-8 with BOM, UTF-16LE with BOM) and scoped version incrementing (machine version in the lower 16 bits, user version in the upper 16 bits).

## Requirements

- Windows with Group Policy support (Pro, Enterprise, Education, IoT Enterprise, Server)
- PowerShell 5.1 or later
- Administrator privileges (the `GroupPolicy` directory is protected)

## Related Tools

- [LGPO.exe](https://www.microsoft.com/en-us/download/details.aspx?id=55319) (Microsoft Security Compliance Toolkit) - import/export local GPO backups
- [PolicyFileEditor](https://www.powershellgallery.com/packages/PolicyFileEditor) - read/write `registry.pol` files directly (no registry sync)
- [GPRegistryPolicy](https://github.com/PowerShell/GPRegistryPolicy) - bulk export registry to `.pol` (no diff/merge)
- [PolicyPlus](https://github.com/Fleex255/PolicyPlus) - GUI Group Policy editor for all Windows editions

## License

MIT
