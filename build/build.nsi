Outfile "install_chickadee.exe"
 
InstallDir $PROGRAMFILES64\Chickadee
 
Section
 
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
    Exec "$INSTDIR\chickadee.exe start"

SectionEnd
 
Section "Uninstall"

    Exec "$INSTDIR\chickadee.exe stop"
    Exec "$INSTDIR\chickadee.exe uninstall"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Chickadee"

    Delete $INSTDIR\chickadee.exe
    Delete $INSTDIR\config.ini
    Delete $INSTDIR\uninstall.exe
    

    RMDir $INSTDIR

SectionEnd
