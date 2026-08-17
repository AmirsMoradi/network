#define MyAppName "SurNet Guardian"
#define MyAppVersion "0.2.0"
#define MyAppExeName "SurNetGuardian.exe"

[Setup]
AppId={{BA4F7A4A-15DF-4B72-8C80-4FB8EB2D8B24}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\SurNet Guardian
DefaultGroupName=SurNet Guardian
OutputBaseFilename=SurNetGuardian-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Files]
Source: "..\dist\SurNetGuardian.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SurNet Guardian"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\SurNet Guardian"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch SurNet Guardian"; Flags: nowait postinstall skipifsilent
