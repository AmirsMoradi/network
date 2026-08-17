$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Virtual environment not found. Run .\install.ps1 first."
}

Write-Host "Running tests..."
.\.venv\Scripts\python.exe -m pytest -q

Write-Host "Installing/updating PyInstaller..."
.\.venv\Scripts\python.exe -m pip install --upgrade pyinstaller

Write-Host "Building SurNet Guardian 0.3.0..."
.\.venv\Scripts\python.exe -m PyInstaller `
    --noconfirm `
    --clean `
    --windowed `
    --onefile `
    --paths . `
    --collect-data customtkinter `
    --collect-submodules pystray `
    --name SurNetGuardian `
    app\main.py

$ExePath = Join-Path $PWD "dist\SurNetGuardian.exe"
if (-not (Test-Path $ExePath)) {
    throw "PyInstaller completed without producing dist\SurNetGuardian.exe"
}
Write-Host "Executable: $ExePath"

$InnoCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
) | Where-Object { $_ -and (Test-Path $_) }

if ($InnoCandidates.Count -gt 0) {
    $Iscc = $InnoCandidates[0]
    Write-Host "Building Windows installer with Inno Setup..."
    & $Iscc "installer\SurNetGuardian.iss"
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup compiler failed with exit code $LASTEXITCODE"
    }
    Write-Host "Installer: installer\output\SurNetGuardian-0.3.0-Setup.exe"
} else {
    Write-Warning "Inno Setup 6 was not found. The EXE is ready; install Inno Setup 6 and compile installer\SurNetGuardian.iss to create the setup package."
}
