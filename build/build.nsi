!include MUI2.nsh

Name "Chickadee NSD"

Outfile "chickadee_installer_win-x64.exe"

InstallDir $PROGRAMFILES64\Chickadee

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Add Files"
    File /oname=$TEMP\npcap.exe "npcap.exe"
SectionEnd

Section "Check Elevation"

    UserInfo::GetAccountType
    Pop $0
    StrCmp $0 "Admin" +3
    MessageBox MB_OK "Please re-launch the installer as an administrator: $0"
    Quit

SectionEnd

Section "Check Npcap Installation"

    ClearErrors
    ReadRegStr $0 HKLM "SOFTWARE\Npcap" ""
    IfErrors 0 skip_npcap_install

    ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\Npcap" ""
    IfErrors 0 skip_npcap_install

    MessageBox MB_YESNO "Npcap is not installed, but is required for Chickadee to run. Would you like to install it now?" IDYES +2
    Goto skip_npcap_install

    SetOutPath $TEMP
    ExecWait "$TEMP\npcap.exe"

    Delete $TEMP\npcap.exe

    skip_npcap_install:

SectionEnd

Section "Install"

    SetOutPath $INSTDIR

    File config.ini
    File chickadee.exe

    WriteUninstaller $INSTDIR\uninstall.exe

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Chickadee" \
            "DisplayName" "Chickadee Network Scan Detector"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Chickadee" \
            "UninstallString" "$\"$INSTDIR\uninstall.exe$\""

    Exec '"$INSTDIR\chickadee.exe" install'

    MessageBox MB_YESNOCANCEL "Make sure to navigate to $INSTDIR\config.ini and set the appropriate interface and agent name before starting the service. Would you like to edit this file now?" IDYES edit_config

    Goto end_messagebox

    edit_config:
    Exec '"$WINDIR\system32\notepad.exe" "$INSTDIR\config.ini"'

    end_messagebox:

SectionEnd

Section "Uninstall"

    Exec '"$INSTDIR\chickadee.exe" stop'
    Exec '"$INSTDIR\chickadee.exe" uninstall'
    Sleep 5000
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Chickadee"
    RMDir /r $INSTDIR

SectionEnd