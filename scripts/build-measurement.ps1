# ============================================================================
# Track Record Enclave - Build Measurement Script (PowerShell)
# ============================================================================
# This script builds the enclave image and calculates its measurement hash.
# The measurement is used to verify attestation reports.
#
# Usage:
#   .\scripts\build-measurement.ps1 [-Push]
# ============================================================================

param(
    [switch]$Push,
    [switch]$KeepTarball
)

$ErrorActionPreference = "Stop"

# Configuration
$ImageName = "track-record-enclave"
$Version = (Get-Content package.json | ConvertFrom-Json).version
$Date = Get-Date -Format "yyyyMMdd"
$MeasurementsDir = "measurements"

Write-Host "============================================" -ForegroundColor Green
Write-Host " Track Record Enclave - Build Measurement" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Version: $Version"
Write-Host "Date: $Date"
Write-Host ""

# Create measurements directory
if (-not (Test-Path $MeasurementsDir)) {
    New-Item -ItemType Directory -Path $MeasurementsDir | Out-Null
}

# Step 1: Build Docker image
Write-Host "Step 1: Building Docker image..." -ForegroundColor Yellow
docker build `
    --no-cache `
    --platform linux/amd64 `
    -t "${ImageName}:${Version}" `
    -t "${ImageName}:latest" `
    .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Docker image built successfully" -ForegroundColor Green
Write-Host ""

# Step 2: Export image to tarball
Write-Host "Step 2: Exporting image to tarball..." -ForegroundColor Yellow
$Tarball = "$MeasurementsDir\$ImageName-$Version.tar"
docker save "${ImageName}:${Version}" -o $Tarball
Write-Host "Tarball: $Tarball"
Write-Host ""

# Step 3: Calculate SHA-384 hash
Write-Host "Step 3: Calculating SHA-384 measurement..." -ForegroundColor Yellow
$Hash = Get-FileHash -Path $Tarball -Algorithm SHA384
$Measurement = $Hash.Hash.ToLower()

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host " MEASUREMENT HASH (SHA-384)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host $Measurement -ForegroundColor Yellow
Write-Host ""

# Step 4: Save measurement to file
$MeasurementFile = "$MeasurementsDir\measurement-$Version-$Date.txt"
$GitCommit = try { git rev-parse HEAD } catch { "N/A" }

$MeasurementContent = @"
Track Record Enclave - Build Measurement
=========================================

Version: $Version
Build Date: $Date
Build Time: $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

Docker Image: ${ImageName}:${Version}
Platform: linux/amd64
Base Image: node:20.18.1-alpine3.21

MEASUREMENT (SHA-384):
$Measurement

Verification Instructions:
1. Build the same image from source:
   docker build --platform linux/amd64 -t ${ImageName}:verify .

2. Export and hash:
   docker save ${ImageName}:verify -o verify.tar
   Get-FileHash verify.tar -Algorithm SHA384

3. Compare with measurement above

4. In attestation report, verify measurement field matches

For SEV-SNP attestation:
- The 'measurement' field in GetAttestationReport response
  should match this hash when running in production enclave.
- Verify AMD signature on attestation report using AMD root certificate.

Git Commit: $GitCommit
"@

$MeasurementContent | Out-File -FilePath $MeasurementFile -Encoding UTF8
Write-Host "Measurement saved to: $MeasurementFile"
Write-Host ""

# Step 5: Calculate source code hash
Write-Host "Step 4: Calculating source code hash..." -ForegroundColor Yellow
$SourceFiles = Get-ChildItem -Path "src" -Recurse -Filter "*.ts" | Sort-Object FullName
$CombinedHash = ""
foreach ($File in $SourceFiles) {
    $FileHash = Get-FileHash -Path $File.FullName -Algorithm SHA256
    $CombinedHash += $FileHash.Hash
}
$CodeHash = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($CombinedHash)
    )
).Replace("-", "").ToLower()

Write-Host "Source Code Hash (SHA-256): $CodeHash"
Write-Host ""
Add-Content -Path $MeasurementFile -Value "Code Hash: $CodeHash"

# Display verification command
Write-Host "============================================" -ForegroundColor Green
Write-Host " Verification Command" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "To verify this build locally:"
Write-Host "  docker save ${ImageName}:${Version} -o verify.tar"
Write-Host "  Get-FileHash verify.tar -Algorithm SHA384"
Write-Host ""
Write-Host "Expected hash:"
Write-Host "  $Measurement"
Write-Host ""

# Clean up tarball
if (-not $KeepTarball) {
    Remove-Item -Path $Tarball -Force
    Write-Host "Tarball removed (use -KeepTarball to preserve)"
}

# Push to registry if requested
if ($Push) {
    Write-Host "Pushing to registry..." -ForegroundColor Yellow
    docker push "${ImageName}:${Version}"
    docker push "${ImageName}:latest"
    Write-Host "Pushed successfully" -ForegroundColor Green
}

Write-Host ""
Write-Host "Build measurement complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Commit measurement file to repository"
Write-Host "2. Publish measurement in GitHub releases"
Write-Host "3. Users can verify by comparing attestation report measurement"
