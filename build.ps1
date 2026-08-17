$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Virtual environment not found. Run .\install.ps1 first."
}

.\.venv\Scripts\python.exe -m pip install --upgrade pyinstaller
.\.venv\Scripts\python.exe -m PyInstaller `
    --noconfirm `
    --clean `
    --windowed `
    --onefile `
    --collect-data customtkinter `
    --name SurNetGuardian `
    app\main.py

Write-Host "Executable: dist\SurNetGuardian.exe"
Write-Host "Compile installer\SurNetGuardian.iss with Inno Setup to create SurNetGuardian-Setup.exe"
