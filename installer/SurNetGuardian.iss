#define MyAppName "SurNet Guardian"
#define MyAppVersion "0.3.0"
#define MyAppPublisher "SurNet"
#define MyAppExeName "SurNetGuardian.exe"

[Setup]
AppId={{BA4F7A4A-15DF-4B72-8C80-4FB8EB2D8B24}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\SurNet Guardian
DefaultGroupName=SurNet Guardian
OutputDir=output
OutputBaseFilename=SurNetGuardian-0.3.0-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayName={#MyAppName}

[Files]
Source: "..\dist\SurNetGuardian.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SurNet Guardian"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\SurNet Guardian"; Filename: "{app}\{#MyAppExeName}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "SurNet Guardian"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch SurNet Guardian"; Flags: nowait postinstall skipifsilent
