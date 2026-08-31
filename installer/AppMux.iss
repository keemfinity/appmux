#define MyAppName "AppMux"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "keemfinity"
#define MyAppURL "https://github.com/keemfinity/appmux"
#define MyAppExeName "AppMux.Manager.exe"
#ifndef PublishDir
#define PublishDir "..\manager\publish"
#endif

[Setup]
AppId={{9B720D85-394B-44E4-B9D7-5979EA40E530}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\AppMux
DefaultGroupName=AppMux
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=AppMux-Setup-{#MyAppVersion}-test-signed
SetupIconFile=..\manager\AppMux.Manager\Assets\AppMux.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
ChangesAssociations=yes
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Excludes: "*.pdb"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\AppMux"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\AppMux"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\appmux.exe"; Parameters: "menu sync"; Flags: runhidden waituntilterminated
Filename: "{app}\appmux.exe"; Parameters: "protocol sync"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "Launch AppMux"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\appmux.exe"; Parameters: "menu remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveAppMuxMenu"
