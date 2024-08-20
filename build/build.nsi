Name "Chickadee NSD Installer"

Outfile "chickadee_installer_win-x64.exe"
 
InstallDir $PROGRAMFILES64\Chickadee
 
Section "Check Elevation"
 
    UserInfo::GetAccountType
    Pop $0
    StrCmp $0 "Admin" +3
    MessageBox MB_OK "Please re-launch the installer as an administrator: $0"
    Return
 
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

    Exec "$INSTDIR\chickadee.exe install"

    MessageBox MB_OK "Make sure to navigate to $INSTDIR\config.ini and set the appropriate interface before starting the service."

SectionEnd
 
Section "Uninstall"

    Exec "$INSTDIR\chickadee.exe stop"
    Exec "$INSTDIR\chickadee.exe uninstall"
    Sleep 5000
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Chickadee"
    RMDir /r $INSTDIR

SectionEnd
