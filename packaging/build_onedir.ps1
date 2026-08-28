$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$LocalPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Spec = Join-Path $PSScriptRoot "VulHub.spec"
$WorkPath = Join-Path $ProjectRoot "build"
$DistPath = Join-Path $ProjectRoot "release"

if (Test-Path -LiteralPath $LocalPython) {
    # Local developer build: keep using the project virtual environment.
    $Python = $LocalPython
} else {
    # CI build: actions/setup-python places Python on PATH, but does not
    # create this repository's local .venv directory.
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $PythonCommand) {
        throw "Build Python was not found. Create .venv locally or provide Python on PATH."
    }
    $Python = $PythonCommand.Source
}

& $Python -m PyInstaller `
    --clean `
    --noconfirm `
    --workpath $WorkPath `
    --distpath $DistPath `
    $Spec

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE"
}

$Executable = Join-Path $DistPath "VulHub-Windows-x64\VulHub.exe"
if (-not (Test-Path -LiteralPath $Executable)) {
    throw "VulHub.exe was not created"
}

$ReleaseReadme = Join-Path $PSScriptRoot "README_RELEASE.txt"
$ReleaseRoot = Split-Path -Parent $Executable
Copy-Item -LiteralPath $ReleaseReadme -Destination (Join-Path $ReleaseRoot "README.txt") -Force

$NonAsciiPaths = Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -Force | ForEach-Object {
    $_.FullName.Substring($ReleaseRoot.Length).TrimStart("\")
} | Where-Object { $_ -match "[^\x00-\x7F]" }
if ($NonAsciiPaths) {
    throw "The release contains non-ASCII paths: $($NonAsciiPaths -join ', ')"
}

$ForbiddenFiles = Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -File | Where-Object {
    $_.Name -match "^(vulhub\.db|.*\.log)$" -or $_.Extension -eq ".py"
}
if ($ForbiddenFiles) {
    throw "The release contains private or source files: $($ForbiddenFiles.FullName -join ', ')"
}

$Archive = Join-Path $DistPath "VulHub-Windows-x64.zip"
if (Test-Path -LiteralPath $Archive) {
    Remove-Item -LiteralPath $Archive -Force
}
Compress-Archive -LiteralPath $ReleaseRoot -DestinationPath $Archive -CompressionLevel Optimal

$Hash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
$HashFile = Join-Path $DistPath "SHA256SUMS.txt"
"$Hash  VulHub-Windows-x64.zip" | Set-Content -LiteralPath $HashFile -Encoding ascii

Write-Host "Build completed: $Executable"
Write-Host "Release archive: $Archive"
Write-Host "SHA-256: $Hash"
