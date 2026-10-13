; Instalador do omapass para Windows (Inno Setup 6).
;
; Compilado pelo workflow windows.yml:
;   ISCC /DMyAppVersion=<versão> /DSourceDir=<pasta do pacote> /O<saída> omapass.iss
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\omapass"
#endif

[Setup]
; Identifica o programa para atualizações e para o desinstalador: não mudar.
AppId={{6C2A5D1E-3B7F-4E8A-9C41-5B0E7A91D2F3}
AppName=omapass
AppVersion={#MyAppVersion}
AppPublisher=Higor Henrique
AppPublisherURL=https://github.com/higorhgon/omapass
AppSupportURL=https://github.com/higorhgon/omapass/issues
DefaultDirName={autopf}\omapass
DisableProgramGroupPage=yes
; Em "Arquivos de Programas" por padrão (pede administrador); quem não tem
; permissão, ou prefere, escolhe instalar só para o próprio usuário.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
; A pasta de destino é perguntada no assistente.
DisableDirPage=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\..\icons\omapass.ico
UninstallDisplayIcon={app}\omapass.exe
UninstallDisplayName=omapass
LicenseFile=..\..\LICENSE
OutputBaseFilename=omapass-{#MyAppVersion}-windows-x64-setup

[Languages]
; O assistente abre no idioma do Windows quando houver tradução.
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
brazilianportuguese.ShortcutsGroup=Atalhos:
brazilianportuguese.StartMenuIcon=Criar um atalho no menu Iniciar
brazilianportuguese.DesktopIcon=Criar um atalho na área de trabalho
brazilianportuguese.LaunchAfter=Abrir o omapass
english.ShortcutsGroup=Shortcuts:
english.StartMenuIcon=Create a Start menu shortcut
english.DesktopIcon=Create a desktop shortcut
english.LaunchAfter=Launch omapass

[Tasks]
; Cada atalho é uma opção do assistente, marcada por padrão e que pode ser
; desmarcada.
Name: "startmenuicon"; Description: "{cm:StartMenuIcon}"; GroupDescription: "{cm:ShortcutsGroup}"
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:ShortcutsGroup}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\omapass"; Filename: "{app}\omapass.exe"; Tasks: startmenuicon
Name: "{autodesktop}\omapass"; Filename: "{app}\omapass.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\omapass.exe"; Description: "{cm:LaunchAfter}"; Flags: nowait postinstall skipifsilent
