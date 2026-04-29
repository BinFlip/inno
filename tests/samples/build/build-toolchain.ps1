param(
    [Parameter(Mandatory=$true)][string]$Version,         # e.g. "6.5.3"
    [Parameter(Mandatory=$true)][string]$Tag,             # e.g. "is-6_5_3"
    [Parameter(Mandatory=$false)][switch]$WithFull,       # build encrypted-full too (6.5+)
    [Parameter(Mandatory=$false)][string]$Filename = "",  # explicit installer filename (overrides default)
    [Parameter(Mandatory=$false)][switch]$Ansi            # tag the slug with `-ansi` (pre-5.3 ANSI builds)
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$work = "$env:USERPROFILE\inno-test"
Set-Location $work

$uninstallRoots = @(
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

# Enumerate every "Inno Setup *" uninstall entry across both registry
# views. Hardcoding `Inno Setup {5,6,7}_is1` misses preview channels and
# anything outside that range, which is how leftover toolchains slipped
# through and silently compiled the next sample with the wrong ISCC.
function Get-InnoSetupRegistryKeys {
    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { return }
            $isInno = ($_.PSChildName -match '^Inno Setup') -or
                      ($props.DisplayName -and $props.DisplayName -match '^Inno Setup')
            if ($isInno) {
                [pscustomobject]@{
                    Key             = $_.PSPath
                    Name            = $_.PSChildName
                    DisplayName     = $props.DisplayName
                    DisplayVersion  = $props.DisplayVersion
                    InstallLocation = $props.InstallLocation
                    UninstallString = $props.UninstallString
                }
            }
        }
    }
}

# 1. Uninstall every Inno Setup currently registered.
$existing = @(Get-InnoSetupRegistryKeys)
foreach ($e in $existing) {
    if (-not $e.UninstallString) { continue }
    $exe = $e.UninstallString.Trim('"')
    if (-not (Test-Path $exe)) { continue }
    Write-Host "[uninstall] $($e.Name) ($($e.DisplayVersion)) -> $exe"
    Start-Process -FilePath $exe -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait | Out-Null

    # Some uninstallers spawn a detached cleanup process even with
    # /VERYSILENT, so wait for the install dir to actually disappear.
    if ($e.InstallLocation) {
        $deadline = (Get-Date).AddSeconds(30)
        while ((Test-Path $e.InstallLocation) -and ((Get-Date) -lt $deadline)) {
            Start-Sleep -Milliseconds 500
        }
        if (Test-Path $e.InstallLocation) {
            Write-Warning "uninstall left $($e.InstallLocation) on disk after 30s"
        }
    }
}

# Refuse to proceed if any ISCC.exe is still on disk under the standard
# prefixes -- otherwise the lookup below could silently use a leftover.
$leftovers = @()
foreach ($prefix in @(
    'C:\Program Files (x86)\Inno Setup',
    'C:\Program Files (x86)\Inno Setup 1',
    'C:\Program Files (x86)\Inno Setup 2',
    'C:\Program Files (x86)\Inno Setup 3',
    'C:\Program Files (x86)\Inno Setup 4',
    'C:\Program Files (x86)\Inno Setup 5',
    'C:\Program Files (x86)\Inno Setup 6',
    'C:\Program Files (x86)\Inno Setup 7'
)) {
    $exe = Join-Path $prefix 'ISCC.exe'
    if (Test-Path $exe) { $leftovers += $exe }
}
if ($leftovers.Count -gt 0) {
    throw "leftover toolchain(s) on disk: $($leftovers -join ', ') -- remove manually before retrying"
}

# 2. Resolve installer filename. Pick the first candidate already on
# disk; download otherwise. (Previously this only checked the first
# candidate name, so a cached `isetup-X-unicode.exe` was ignored.)
$candidates = @()
if ($Filename) {
    $candidates += $Filename
} else {
    $candidates += "innosetup-$Version.exe"
    $candidates += "isetup-$Version-unicode.exe"
    $candidates += "isetup-$Version.exe"
}

$installer = $null
foreach ($c in $candidates) {
    if (Test-Path $c) { $installer = $c; break }
}

if (-not $installer) {
    $major      = $Version.Split('.')[0]
    $majorMinor = ($Version.Split('.')[0..1] -join '.')
    $bases = @(
        "https://github.com/jrsoftware/issrc/releases/download/$Tag",
        "https://files.jrsoftware.org/is/$major",
        "https://files.jrsoftware.org/is/$majorMinor"
    )
    foreach ($name in $candidates) {
        foreach ($base in $bases) {
            $url = "$base/$name"
            Write-Host "[download try] $url"
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $name -ErrorAction Stop
                $installer = $name; break
            } catch {
                Write-Host "  -> $($_.Exception.Message.Split([Environment]::NewLine)[0])"
            }
        }
        if ($installer) { break }
    }
    if (-not $installer) { throw "all download URLs failed for $Version" }
}
Write-Host "[picked] $installer"

# 3. Install silently. Surface a non-zero exit code instead of logging
# it and continuing.
Write-Host "[install] $installer"
$p = Start-Process -FilePath ".\$installer" -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/SP-','/NOICONS' -Wait -PassThru
Write-Host "[install] ExitCode=$($p.ExitCode)"
if ($p.ExitCode -ne 0) { throw "installer exited $($p.ExitCode)" }

# 4. Locate ISCC.exe via the registry entry whose DisplayVersion matches
# what we just installed. The previous "scan 7→6→5" fallback would
# silently pick whatever leftover toolchain ranked highest.
$installed = @(Get-InnoSetupRegistryKeys) | Where-Object {
    $_.DisplayVersion -and (
        $_.DisplayVersion -eq $Version -or
        $_.DisplayVersion -like "$Version.*" -or
        $_.DisplayVersion -like "$Version*"
    )
}
if ($installed.Count -eq 0) {
    Write-Host "[debug] all Inno Setup keys after install:"
    Get-InnoSetupRegistryKeys | Format-Table Name, DisplayVersion, InstallLocation -AutoSize | Out-Host
    throw "no Inno Setup uninstall key matches version $Version -- install likely failed silently"
}
$entry = $installed[0]
Write-Host "[version] DisplayVersion=$($entry.DisplayVersion) (key=$($entry.Name))"

$iscc = $null
if ($entry.InstallLocation) {
    $candidate = Join-Path $entry.InstallLocation 'ISCC.exe'
    if (Test-Path $candidate) { $iscc = $candidate }
}
if (-not $iscc) { throw "ISCC.exe not found at $($entry.InstallLocation)" }
Write-Host "[iscc] $iscc"

# 4b. Stage ISCrypt.dll for pre-6.4 Inno Setup. The pre-XChaCha20
# encryption module shipped as a separate DLL that the user had to
# download manually; without it ISCC errors with "Cannot use encryption
# because ISCrypt.dll is missing." 6.4+ has XChaCha20 built in and
# ignores the file (issrc whatsnew.htm:917). Drop a copy in
# `inno-test\ISCrypt.dll` once and this step picks it up automatically.
$crypt = "ISCrypt.dll"
if ((Test-Path $crypt) -and $entry.InstallLocation) {
    $dest = Join-Path $entry.InstallLocation $crypt
    if (-not (Test-Path $dest)) {
        Copy-Item -Force $crypt $dest
        Write-Host "[iscrypt] copied -> $dest"
    }
} elseif (-not (Test-Path $crypt)) {
    Write-Host "[iscrypt] $crypt not present in $(Get-Location); encrypted builds may fail on Inno < 6.4"
}

# 5. Build plain + encrypted (+ encrypted-full if requested).
$slug = $Version.Replace('.', '_')
if ($Ansi) { $slug = "$slug" + "_ansi" }

del plain.exe -ErrorAction SilentlyContinue
del encrypted.exe -ErrorAction SilentlyContinue
del encrypted-full.exe -ErrorAction SilentlyContinue

Write-Host "[build] plain.iss"
& $iscc plain.iss /Q
if ($LASTEXITCODE -ne 0) { throw "plain build failed" }
if (-not (Test-Path plain.exe)) { throw "plain.exe not produced" }
Move-Item -Force plain.exe "plain-tool$slug.exe"

Write-Host "[build] encrypted.iss"
& $iscc encrypted.iss /Q
if ($LASTEXITCODE -ne 0) { throw "encrypted build failed" }
if (-not (Test-Path encrypted.exe)) { throw "encrypted.exe not produced" }
Move-Item -Force encrypted.exe "enc-files-tool$slug.exe"

if ($WithFull) {
    Write-Host "[build] encrypted-full.iss"
    & $iscc encrypted-full.iss /Q
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "encrypted-full build failed (Encryption=full directive may not exist on $Version)"
    } elseif (-not (Test-Path encrypted-full.exe)) {
        Write-Warning "encrypted-full.exe not produced"
    } else {
        Move-Item -Force encrypted-full.exe "enc-full-tool$slug.exe"
    }
}

Write-Host "[done] $Version"
Get-ChildItem "*tool$slug*" | Select-Object Name, Length
