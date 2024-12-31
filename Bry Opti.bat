@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

:: v0.1 
:: Intial Release

:: v0.2
:: Fixed PowerRun "Allow Command Line" by changing all Reg add to Reg.exe add
:: Added Disable Devices
:: Both Apps and Systems are configured to be Dark Mode instead of just apps
:: Optimized code
:: Configured Powersaving Features




:: Run as Admin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
::--------------------------------------


:: Enabling Delayed Expansion
setLOCAL EnableDelayedExpansion


:: Set Variable for DevManView
set dmv=call "resources\DevManView.exe" /disable

:: Putting Title of the Batch Script
title Bry's Script


echo.                                                  
echo.
echo                                ██████╗ ██████╗ ██╗   ██╗     █████╗ ██╗ ██████╗ 
echo                                ██╔══██╗██╔══██╗╚██╗ ██╔╝    ██╔══██╗██║██╔═══██╗
echo                                ██████╔╝██████╔╝ ╚████╔╝     ███████║██║██║   ██║
echo                                ██╔══██╗██╔══██╗  ╚██╔╝      ██╔══██║██║██║   ██║
echo                                ██████╔╝██║  ██║   ██║       ██║  ██║██║╚██████╔╝
echo                                ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝╚═╝ ╚═════╝                                                                       
echo.
echo.  
echo                                                        Hello, %username%
echo.
echo I highly recommend to create a restore point as the script does not automatically create one as of now or some sort of backup.
pause



:: Getting GPU Architecture
:: Credit to Zusier 
:: Useful for distinguishing which GPU user has
if "%PROCESSOR_ARCHITECTURE%" EQU "AMD64" (
  echo Processor: %PROCESSOR_ARCHITECTURE% >> log.txt
) else (
  cls
  echo Processor: %PROCESSOR_ARCHITECTURE% >> log.txt
  echo 32-bit or arm sytem architecture detected. It is not recommended to run on unsupported CPUs.
  echo Press space to continue or exit.
  pause
)
set "GPU="
for /F "tokens=* skip=1" %%n in ('WMIC path Win32_VideoController get Name ^| findstr "."') do (
  echo GPU: %%n >> log.txt
  >nul find "NVIDIA" log.txt && (
    set GPU=NVIDIA
  ) 
  >nul find "AMD" log.txt && (
    set GPU=AMD
  )
)
echo GPU: %GPU%


goto checkchoc


:checkchoc
set chocoPath=%ProgramData%\chocolatey\choco.exe

if exist "%chocoPath%" (
    echo Chocolatey exists
    goto choc
) else (
    echo Chocolatey isn't installed.
    echo Running install script
    PowerShell -executionpolicy bypass -file "resources\choco install.ps1" >> log.txt
    goto choc
)

:choc
:: Disables the Confirmation Prompt when Installing a Program through Chocolately
choco feature enable -n=allowGlobalConfirmation >nul 2>&1 
:: Useful for downloding applications inside a script
:: Found out about it reading through Artanis' script, very useful
if exist "%ProgramData%\chocolatey\lib\curl" ( goto vr 
) else (
 choco install curl >> log.txt
   goto vr
)

:vr
:: Install Visual Runtimes
:: Rather show progress than silent install, espcially if this goes public
call "resources\vcredist.exe" /ai /gm2


cls

:: Disable UAC
for %%i in (
  EnableLUA 
  ConsentPromptBehaviorAdmin
  PromptOnSecureDesktop
  FilterAdministratorToken
  ) do Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "%%i" /t REG_DWORD /d "0" /f


for %%a in (
  AxInstSV
  tzautoupdates
  NaturalAuthentication
  dmwappushservice
  MapsBroker
  lfsvc
  SharedAccess
  lltdsvc
  PcaSvc
  CDPUserSvc
  NetTcpPortSharing
  CscService
  PrintNotify
  QWAVE
  RemoteAccess
  SensorDataService 
  SensrSvc
  SensorService
  ShellHWDetection
  ScDeviceEnum
  SSDPSRV
  WiaRpc
  upnphost
  UserDataSvc
  UevAgentService
  FrameServer
  stisvc
  wisvc
  icssvc    
  CompositeBus
  NdisVirtualBus
) do (
  call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\%%a" /v "Start" /t REG_DWORD /d "4" /f
) 
cls



echo Applying personal/useful regs
:: Privacy/Disabling Telemetry
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f


:: DMA Remapping Disable 
for /f %%i in ('Reg.exequery "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\" ') do (
	Reg.exe add "%%i" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
)


:: add batch to new file menu
:: More conveient, personally for me
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Classes\.bat\ShellNew" /v "ItemName" /t REG_EXPAND_SZ /d "@C:\Windows\System32\acppage.dll,-6002" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Classes\.bat\ShellNew" /v "NullFile" /t REG_SZ /d "" /f >nul 2>&1

:: add Reg.exeto new file menu
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Classes\.reg\ShellNew" /v "ItemName" /t REG_EXPAND_SZ /d "@C:\Windows\regedit.exe,-309" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Classes\.reg\ShellNew" /v "NullFile" /t REG_SZ /d "" /f >nul 2>&1


:: Enable Dark Mode
:: Do you?
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f

:: CRSS High Priority
for %%a in (csrss) do (
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a.exe\PerfOptions" /v IoPriority /t REG_DWORD /d "3" /f
)

:: Lock Screen
:: Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d "1" /f 
:: Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" /v "AllowLockScreen" /t REG_DWORD /d "0" /f 
:: Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f 


:: Disable Task View on Taskbar
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f

:: Hide Search Box on Taskbar
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f

Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f

:: Diagnostics and Privacy
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
sc stop DiagTrack
sc stop dmwappushservice
sc delete DiagTrack
sc delete dmwappushservice


:: Disable Transparency
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f


:: Deleting Intel and AMD Microcode
:: Can cause BSOD on Windows 11 24H2
:: takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a  
:: icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant Administrators:(F) 
:: ren "%WinDir%\System32\GameBarPresenceWriter.exe" "GameBarPresenceWriter32131dada.exe"
:: takeown /f "%WinDir%\System32\backgroundTaskHost.exe" /a /r /d y
:: ren "%WinDir%\System32\backgroundTaskHost.exe" "backgroundTaskHost2313dada.exe"
:: takeown /f "%WinDir%\System32\mcupdate_AuthenticAMD.dll" /a
:: icacls "%WinDir%\System32\mcupdate_AuthenticAMD.dll" /grant Administrators:(F)
:: del "%WinDir%\System32\mcupdate_AuthenticAMD.dll" /s /f /q 
:: takeown /f "%WinDir%\System32\mcupdate_GenuineIntel.dll" /a 
:: icacls "%WinDir%\System32\mcupdate_GenuineIntel.dll" /grant Administrators:(F) 
:: del "%WinDir%\System32\mcupdate_GenuineIntel.dll" /s /f /q

:: Notifications
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f


:: Mouse
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000000a0000000000000004001000000000000800200000000000000050000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000" /f

:: Location
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f

:: Biometrics
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f

:: set .ps1 files to open with PowerShell by default
Reg.exe add "HKCR\Microsoft.PowerShellScript.1\Shell\Open\Command" /ve /t REG_SZ /d "\"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe\" -File \"%%1\"

:: Program Compatibility Assistant
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d 4 /f
 

:: System Responsiveness
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f


::Disable Memory Compression
PowerShell "Disable-MMAgent -MemoryCompression" >nul

:: Windows Customer Imrpovement Program
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f

:: Win32 Priority Seperation
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f


:: Disable Devices 
%dmv% "WAN Miniport (IKEv2)"
%dmv% "WAN Miniport (IP)"
%dmv% "WAN Miniport (IPv6)
%dmv% "WAN Miniport (L2TP)"
%dmv% "WAN Miniport (Network Monitor)"
%dmv% "WAN Miniport (PPPOE)"
%dmv% "WAN Miniport (PPPOE)"
%dmv% "WAN Miniport (PPTP)"
%dmv% "WAN Miniport (SSTP)"
%dmv% "Composite Bus Enumerator"
%dmv% "NDIS Virtual Network Adapter Enumerator"

:: Gamebar Presence Writer
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d 0 /f

:: Windows Explorer
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
cls

echo [101;41mWould you like to Improve Desktop Wallpaper:[0m
echo note: May need to set a desktop wallpaper again for it to take affect
echo Press "Y" to apply.
echo Press "N" to skip.
echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
echo.
:apply
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t "REG_DWORD" /d "100" /f
echo.


goto :next


:next 
cls
echo [101;41mDisable Xbox Services?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%" =="N" goto next

:apply
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XblAuthManage" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
echo.


goto :next

:next
cls
echo [101;41mDisable Windows Store?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.


:apply
for %%s in (
  iphlpsvc
  ClipSVC
  AppXSvc
  LicenseManager
  NgcSvc
  NgcCtnrSvc
  wlidsvc
  TokenBroker
  WalletService
  DoSvc
) do (
  Reg.exe add "HKLM\SYSTEM\ControlSet\Services\%%s" /v "Start" /t REG_DWORD /d "4" /f
)
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableStoreApps" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemsettingsDownloadMode" /t REG_DWORD /d 0 /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemsettingsDownloadMode" /t REG_DWORD /d 0 /f 
echo.

goto next

:next
cls
echo [101;41mDisable Powersaving Features?:[0m
echo note: Skip on a Laptop unless you have good enough cooling
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next

:apply

for %%i in (
  EnhancedPowerManagementEnabled AllowIdleIrpInD3 EnableSelectiveSuspend DeviceSelectiveSuspended
SelectiveSuspendEnabled SelectiveSuspendOn EnumerationRetryCount ExtPropDescSemaphore WaitWakeEnabled
D3ColdSupported WdfDirectedPowerTransitionEnable EnableIdlePowerManagement IdleInWorkingState) do for /f %%a in ('Reg.exequery "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%i"^| findstr "HKEY"') do Reg.exe add "%%a" /v "%%i" /t REG_DWORD /d "0" /f 
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 
powercfg powercfg -setactive "ee9a42b02-d5df-448d-aa00-03f14749eb61" 
Reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
powercfg /h off

goto next


:next
cls
echo [101;41mDisable SettingSync? (syncs settings to microsoft account):[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.

:apply
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync" /v "SyncPolicy" /t Reg_DWORD /d 5 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Accessibility" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\AppSync" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Browsersettings" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Credentials" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\DesktopTheme" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Language" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\PackageState" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Personalization" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\StartLayout" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Windows" /v "Enabled" /t Reg_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablesettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablesettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableAppSyncsettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableAppSyncsettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableApplicationsettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableApplicationsettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableCredentialssettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableCredentialssettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableDesktopThemesettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableDesktopThemesettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablePersonalizationsettingSync" /t Reg_DWORD /d 2 /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablePersonalizationsettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableStartLayoutsettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableStartLayoutsettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableSyncOnPaidNetwork" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWebBrowsersettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWebBrowsersettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWindowssettingSync" /t Reg_DWORD /d 2 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWindowssettingSyncUserOverride" /t Reg_DWORD /d 1 /f
Echo.


goto :next


:next
cls
echo [101;41mDisable Automatic Windows Update?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.

:apply
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t REG_DWORD /d "3" /f
goto :next

:next
cls
echo [101;41mDisable Windows Defender and Smartscreen?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.

:apply
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wdboot" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wdfilter" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wdnisdrv" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mssecflt" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1"
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
call "resources\PowerRun.exe" /SW:0 Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
echo.

goto :next


:next
cls
echo [101;41mDisable Bluetooth Support?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.



:apply
for %%z in (
  DoSvc
  bthserv
  BthAvctpSvc
  NaturalAuthentication
  BluetoothUserService
) do (
  Reg.exe add "HKLM\SYSTEM\ControlSet\Services\%%z" /v "Start" /t REG_DWORD /d "4" /f
)
Echo.


goto :next

:next
cls
echo [101;41mApply SVC Split Threshold?:[0m
echo Note: This has no effect on Performance
echo Simply just groups the svchost together
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next

:apply
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%i
set /a ram=%mem% + 1024000
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f 
echo.


goto :next


:next
cls
echo [101;41mDisable Windows Firewall?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.

:apply
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d 00000001 /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d 00000001 /f
Echo.


goto :next


:next
cls
echo [101;41mDisable Hyper-V? (Other virtulization should work):[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.
:apply
for %%t in (
  HvHost
  vmickvpexchange
  vmicguestinterface
  vmicshutdown
  vmicheartbeat
  vmicvmsession
  vmicrdv
  vmictimesync
  vmicvss
) do (
  Reg.exe add "HKLM\SYSTEM\ControlSet\Services\%%t" /v "Start" /t REG_DWORD /d "4" /f
)
Echo.


goto :next

:next
cls
echo [101;41mDisable Windows Error Reporting and Windows Push Notifications?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.
:apply
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f
Echo.


:next
cls
echo [101;41mDisable Print?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next


:apply
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo.


goto :next

:next
cls
echo [101;41mDisable Smart Card Support?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next
Echo.

:apply
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo.
echo [101;41mSmart Cards has been disabled.[0m

goto next

:next
cls
echo [101;41mDebloat Windows?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next


:apply
:: Default Apps
call :DOWNLOAD https://github.com/valleyofdoom/AppxPackagesManager/releases/download/1.4.3/AppxPackagesManager.exe "%UserProfile%\Documents\AppxPackagesManager.exe" >nul 2>&1
call "%UserProfile%\Documents\AppxPackagesManager.exe" >nul 2>&1
:: Remove Cortana
takeown /f "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /r /a
icacls "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /grant administrators:F /t
ren "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" Microsoft.Windows.Cortana_cw5n1h2txyewy.old

goto :next

:next
cls
echo [101;41mDisable and Unistall Microsoft Edge?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
set /P choice=  [101;42mY / N:[0m  
if /I "%choice%"=="Y" goto apply
if /I "%choice%"=="N" goto next

:apply
echo Please be patient, this may take a moment
:: Finding and deleting any scheduled tasks that have "Edge" in the name
for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "MicrosoftEdge"') do schtasks /Delete /TN %%x /F
sc config <service_name> start= disabled
if exist "C:\Program Files (x86)\Microsoft\Edge" do (
  :: Kill Microsoft Edge
  Taskkill /f /im msedge.exe
  :: Delete Related Services
  sc stop edgeupdatem
  sc stop edgeupdate
  sc stop MicrosoftEdgeElevationService
  sc delete edgeupdatem
  sc delete edgeupdate
  sc delete MicrosoftEdgeElevationService
  :: Delete Directories
  rd /s /q "%LocalAppData%\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
  rd /s /q "%LocalAppData%\Microsoft\Edge"
  rd /s /q "C:\Program Files (x86)\Microsoft\Edge"
  rd /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate"
  :: Deleting Shortcuts
  rd /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
  rd /s /q "%UserProfile%\Desktop\Microsoft Edge.lnk"
  rd /s /q "%Appdata%\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk"
  rd /s /q "%Appdata%\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk"
  if exist "C:\Program Files (x86)\Microsoft\EdgeCore" do (
    rd /s /q "C:\Program Files (x86)\Microsoft\EdgeCore"
    if exist "C:\Program Files (x86)\Microsoft\EdgeWebView" do (
      rd /s /q "C:\Program Files (x86)\Microsoft\EdgeWebView"
    )
  )

)

goto :next

:next
cls
echo [101;41mDisable and Uninstall OneDrive?:[0m
echo Press "Y" to apply.
echo Press "N" to skip.
Echo.
SET /P choice=  [101;42mY / N:[0m  
IF /I "%choice%"=="Y" goto apply
IF /I "%choice%"=="N" goto finish
Echo.

:apply
:: Credits to Zusier
:: Kill onedrive
taskkill /f /im OneDrive.exe 
:: run OneDrive uninstall if exists
if exist %SystemRoot%\System32\OneDriveSetup.exe (
	start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall
) else (
	start /wait %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
)
:: Delete any scheduled tasks that have "Onedrive" in the name
for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F
:: remove OneDrive shortcuts (preinstalled)
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /s /f /q
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
del "%USERPROFILE%\Links\OneDrive.lnk" /s /f /q
:: remove OneDrive related directories
rd "%UserProfile%\OneDrive" /q /s 
rd "%SystemDrive%\OneDriveTemp" /q /s
rd "%LocalAppData%\Microsoft\OneDrive" /q /s
rd "%ProgramData%\Microsoft OneDrive" /q /s
:: delete related registry folders
Reg.exedelete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
Reg.exedelete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
:: disable onesync
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_402ac" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d 1 /f
:: remove onedrive from explorer/quick access
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
Reg.exe add "HKCR\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f

goto smp


:smp
cls
set /p choice=Do you want to disable Spectre and Meltdown protections? [Y/N]?
if /I "%choice%"=="Y" goto :Ys
if /I "%choice%"=="N" goto :noM

:Ys
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1

:noM
:: Fast Startup
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

cls
set /P z=Do you want to enable FSE and disable GameBar? [Y/N]?
if /I "%c%" EQU "Y" goto :FSE
if /I "%c%" EQU "N" goto :noF

:FSE
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t reg_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t reg_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t reg_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t reg_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t reg_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t reg_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t reg_DWORD /d "2" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t reg_DWORD /d "1" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t reg_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t reg_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t reg_DWORD /d "2" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t reg_DWORD /d "2" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t reg_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t reg_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t reg_DWORD /d "0" /f 

:noF
:: Enable MSI mode on GPU
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v MSISupported /t REG_DWORD /d 0x00000001 /f 
)

if "%GPU%" EQU "AMD" (
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f
  Reg.exe add "HKLM\System\CurrentControlSet\Services\AMD Crash Defender Service" /v "Start" /t REG_DWORD /d "4" /f 
  Reg.exe add "HKLM\System\CurrentControlSet\Services\AMD External Events Utility" /v "Start" /t REG_DWORD /d "4" /f
  Reg.exe add "HKLM\System\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d "4" /f
)
if "%GPU%" EQU "NVIDIA" (
  Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f
  Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
  Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
  Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
  Reg.exedelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f
:: remove telemetry packages
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)

 del /s %systemdrive%\System32\DriverStore\FileRepository\NvTelemetry*.dll
 rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2
 rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2
 :: Disable Nvidia tasks/services
 schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
 schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
 schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
)


:: BCDedits
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick Yes


:: Disabling Nagele Algorithm
:: https://www.mikemartin.co/system_guides/hardware/networking/disable_nagle_algorithm
for /f %%i in ('wmic path win32_networkadapter get GUID^| findstr "{"') do (
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f 
) 




:: Google Chrome Services
if exist "C:\Program Files\Google\Chrome" do (
  sc stop "gupdate" & sc config "gupdate" start=disabled
  sc stop "gupdatem" & sc config "gupdatem" start=disabled
  schtasks /change /disable /tn "GoogleUpdateTaskMachineCore"
  schtasks /change /disable /tn "GoogleUpdateTaskMachineUA"
)

:: Disable FireFox Telemtry
if exist "C:\Program Files\Mozilla Firefox" do (
  Reg.exe addHKLM\SOFTWARE\Policies\Mozilla\Firefox /v DisableTelemetry /t REG_DWORD /d 1 /f
)


del /s /f /q %temp%\*.*
del /s /f /q %WinDir%\temp\*.*

echo Finished configuration
echo.
echo.
echo Would you lik to view the Credits? Y/N
set /P choice=
if "%choice%"=="Y" goto :creds
if "%choice%"=="N" goto :end


:creds
cls
call:MSGBOX "Artanis - Some Windows Configuration as well as use of Curl (Learning from his script and inspiration)\nZusier - OneDrive, Some Windows Configuration  \nAMIT - Powersaving Features\nTimecard - His research about PC configuration and setup\nStack Overflow among with other forums - Coding Help/Troubleshooting.\n\n                                                             " vbInformation "Credits"

goto :end


:end
exit



:MSGBOX 
echo WScript.Quit Msgbox(Replace("%~1","\n",vbCrLf),%~2,"%~3") >"%TMP%\msgbox.vbs"
cscript /nologo "%TMP%\msgbox.vbs"
set "exitCode=!ERRORLEVEL!" & del /f /q "%TMP%\msgbox.vbs" >nul 2>&1
exit /b %exitCode%



:: Very useful features that was/can be used.
:: Credits to Artanis
:DOWNLOAD
curl.exe -sS -L -o %2 %1 >nul 2>&1

::UNZIP
:: powershell "Expand-Archive -Path %1 -DestinationPath %2"
