# ==========================================
# MULTI-STAGE RANSOMWARE SIMULATION (TIMESTAMP VERSION)
# ==========================================

$folderPath = "C:\temp"
$fileCount = 40
$failCount = 0
$failThreshold = 2

# Function to get timestamp
function Get-TimeStamp {
    return (Get-Date).ToString("HH:mm:ss.fff")
}

function Log {
    param ($msg)
    Write-Host "[$(Get-TimeStamp)] $msg"
}

Log "Stage 1: Preparing environment"

# Setup
if (!(Test-Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

Get-ChildItem $folderPath -Recurse -ErrorAction SilentlyContinue | `
    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# Create files
1..$fileCount | ForEach-Object {
    $ext = @("txt","docx","pdf","xlsx") | Get-Random
    Set-Content "$folderPath\file_$_.${ext}" "DATA $_"
}

Log "Files created: $fileCount"

# Ransom note
Set-Content "$folderPath\README_RESTORE_FILES.txt" "Simulation"

Start-Sleep -Seconds 1

# ==========================================
# Stage 2: File access
# ==========================================

Log "Stage 2: Mass file access"

Get-ChildItem $folderPath -File | ForEach-Object {
    try {
        Get-Content $_.FullName | Out-Null
    } catch {}
}

Start-Sleep -Seconds 1

# ==========================================
# Stage 3: Ransomware simulation
# ==========================================

function Invoke-RansomBehavior {
    param ($filePath)

    try {
        if ($filePath -like "*.lockbit") {
            return $true
        }

        Set-Content $filePath ("ENC_" + (Get-Random)) -ErrorAction Stop
        Rename-Item $filePath ($filePath + ".lockbit") -ErrorAction Stop

        Log "Processed: $filePath"
        return $true
    }
    catch {
        Log "Blocked: $filePath"
        return $false
    }
}

Log "Stage 3: Starting ransomware simulation"

while ($true) {

    $targets = Get-ChildItem $folderPath -File |
        Where-Object { $_.Name -notlike "*.lockbit" -and $_.Name -notlike "README*" } |
        Select-Object -First 3

    if ($targets.Count -eq 0) {
        Log "No more files to process"
        break
    }

    foreach ($file in $targets) {

        $result = Invoke-RansomBehavior $file.FullName

        if (-not $result) {
            $failCount++
        }

        # STOP condition (simulate EDR kill)
        if ($failCount -ge $failThreshold) {
            Log "=========================================="
            Log "EDR DETECTED ACTIVITY -> TERMINATING"
            Log "No further files will be impacted"
            Log "=========================================="
            exit
        }

        Start-Sleep -Milliseconds 150
    }

    Start-Sleep -Milliseconds 300
}
