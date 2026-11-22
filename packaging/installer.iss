; Instalador de win11-triage (Inno Setup 6).
; Compilar:  ISCC.exe /DAppVersion=2.0.0 packaging\installer.iss   →   dist\win11-triage-setup-2.0.0.exe

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "win11-triage"
#define AppExe "win11-triage-gui.exe"

[Setup]
AppId={{B1E7A0F2-5C3D-4E8A-9F21-7D6C2A1B9E44}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
AppPublisherURL=https://github.com/davidzabalaasir-create/Win11_triage
AppSupportURL=https://github.com/davidzabalaasir-create/Win11_triage/issues
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Por defecto se instala solo para el usuario (sin pedir administrador); el asistente permite elegir.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=win11-triage-setup-{#AppVersion}
SetupIconFile=..\win11_triage\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName} {#AppVersion}
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
spanish.Sysinternals=Instalar las herramientas de Sysinternals con winget (Autoruns, Sigcheck, TCPView)
english.Sysinternals=Install Sysinternals tools with winget (Autoruns, Sigcheck, TCPView)
spanish.AddToPath=Añadir la versión de consola (win11-triage) al PATH
english.AddToPath=Add the console version (win11-triage) to PATH
spanish.Components=Componentes:
english.Components=Components:
spanish.Installing=Instalando %1 con winget…
english.Installing=Installing %1 with winget…

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "sysinternals"; Description: "{cm:Sysinternals}"; GroupDescription: "{cm:Components}"
Name: "addtopath"; Description: "{cm:AddToPath}"; GroupDescription: "{cm:Components}"; Flags: unchecked

[Files]
Source: "..\dist\win11-triage\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\.env.example"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Triaje defensivo de Windows"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
  Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{cmd}"; Parameters: "/c winget install --id Microsoft.Sysinternals.Autoruns -e --silent --accept-source-agreements --accept-package-agreements"; \
  StatusMsg: "{cm:Installing,Autoruns}"; Tasks: sysinternals; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/c winget install --id Microsoft.Sysinternals.Sigcheck -e --silent --accept-source-agreements --accept-package-agreements"; \
  StatusMsg: "{cm:Installing,Sigcheck}"; Tasks: sysinternals; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/c winget install --id Microsoft.Sysinternals.TCPView -e --silent --accept-source-agreements --accept-package-agreements"; \
  StatusMsg: "{cm:Installing,TCPView}"; Tasks: sysinternals; Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;
