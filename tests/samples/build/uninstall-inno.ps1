$key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1'
$rec = Get-ItemProperty $key -ErrorAction SilentlyContinue
if ($null -eq $rec) {
    Write-Output 'no install found'
    exit 0
}
$raw = $rec.UninstallString
Write-Output "raw=$raw"
$exe = $raw.Trim('"')
if (-not (Test-Path $exe)) {
    Write-Output "uninstaller not at: $exe"
    exit 1
}
$p = Start-Process -FilePath $exe -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
"ExitCode=$($p.ExitCode)"
