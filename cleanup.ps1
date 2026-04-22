# PML Test Cleanup v4
$ErrorActionPreference = 'SilentlyContinue'
Write-Host '[*] Removing file artifacts...'
$files = @(
    "$env:APPDATA\Microsoft\Windows\pml_s3.vbs",
    "$env:TEMP\pml_s4.js",
    "$env:TEMP\pml_done.txt"
)
foreach ($f in $files) {
    if (Test-Path $f) { Remove-Item $f -Force
        Write-Host "    [+] Removed: $f" }
}
Write-Host '[*] Removing registry persistence key...'
$rk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Get-ItemProperty -Path $rk -Name 'PMLTestStub' -EA SilentlyContinue) {
    Remove-ItemProperty -Path $rk -Name 'PMLTestStub' -Force
    Write-Host '    [+] Removed Run key: PMLTestStub'
}
Write-Host '[+] Cleanup complete. Restore PML File action to original setting.'
