# Tested on windows server 2012

$InstallDir = "C:\webpagetest"
$TempDir = "C:\wpttemp"
$URL = "https://github.com/WPO-Foundation/webpagetest/releases/download/WebPageTest-2.19/webpagetest_2.19.zip"
$ZipFile = "$TempDir\webpagetest_2.19.zip"
$Username = [Environment]::UserName
$Password = "iWqDa2W6COY3r"
$LicenceKey = "F9FNP-X2KQW-4YG6H-GT77B-MY3WM"
$ThisHost = [Environment]::UserDomainName
# add windows license
# from the standard eval edition
DISM /online /Set-Edition:ServerStandard /ProductKey:$LicenceKey /AcceptEula

# fr-Fr keyboard
Set-WinUserLanguageList -LanguageList fr-FR

# extend partition size of C drive
$MaxSize = (Get-PartitionSupportedSize -DriveLetter c).sizeMax
Resize-Partition -DriveLetter c -Size $MaxSize

# dns google
netsh interface ip add dns name="Ethernet" addr=8.8.4.4 index=1
netsh interface ip add dns name="Ethernet" addr=8.8.8.8 index=2

# automatic windows update
$AUSettigns = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AUSettigns.NotificationLevel = 4
$AUSettigns.Save()

# disable cursor shadow for RPC progs
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 00000003
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "CursorShadow" -Value 00000000
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name 'UserPreferencesMask' -Value ([byte[]](0x9E,0x1E,0x07,0x80,0x12,0x00,0x00,0x00))


# disable-ie-esc-admin
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}\" -Name "IsInstalled" -Value 0

# disable-ie-esc-admin
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}\" -Name "IsInstalled" -Value 0

# disable screensave
Set-ItemProperty "HKCU:\Control Panel\Desktop\" -Name "ScreenSaveActive" -Value 0

# disable-monitor-timeout
$CurrentVal = POWERCFG /QUERY SCHEME_BALANCED SUB_VIDEO VIDEOIDLE | Select-String -pattern "Current AC Power Setting Index:"

If ($CurrentVal -like "*0x00000000*") {
  Write-Output "changed=no comment='Display Timeout already set to Never.'"
} Else {
  POWERCFG /CHANGE -monitor-timeout-ac 0
  Write-Output "changed=yes comment='Display Timeout set to Never.'"
}

# disable-shutdown-tracker
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability\" -Name "ShutdownReasonUI" -Value 0

# disable-uac
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

# disable-server-manager
$CurrentState = Get-ScheduledTask -TaskName "ServerManager"

If ($CurrentState.State -eq "Ready") {
  Get-ScheduledTask -TaskName "ServerManager" | Disable-ScheduledTask
  Write-Output "changed=yes comment='Server Manager disabled at logon.'"
} Else {
  Write-Output "changed=no comment='Server Manager already disabled at logon.'"
}

# update password
Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools
$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
Set-ADAccountPassword $Username -NewPassword $securePassword –Reset

# auto-admin-logon
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "AutoAdminLogon" -Value 1

# default-user-name
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "DefaultUserName" -Value $Username

# default-password
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "DefaultPassword" -Value $Password

# dont-display-last-user
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "DontDisplayLastUserName" -Value 1

# last-used-user-name
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "LastUsedUsername" -Value $Username

# last-loggedon-user
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\" -Name "LastLoggedOnUser" -Value $Username

# stable-clock
$useplatformclock = bcdedit | Select-String -pattern "useplatformclock        Yes"

if ($useplatformclock) {
  Write-Output "changed=no comment='Platform Clock Already Enabled.'"
} Else {
  bcdedit /set  useplatformclock true
  Write-Output "changed=yes comment='Platform Clock Enabled.'"
}

## ----- INSTALLATION WEBPAGETEST

# manage-temp-dir
New-Item -ItemType directory -Path $TempDir

# manage-install-dir
New-Item -ItemType directory -Path $InstallDir

# extract-installer
function Expand-ZIPFile($file, $destination) {

  $shell = new-object -com shell.application
  $zip = $shell.NameSpace($file)

  foreach($item in $zip.items()) {
    $shell.Namespace($destination).copyhere($item)
  }
}

$TestDir = "$InstallDir\agent"

If (Test-Path $TestDir -pathType container) {
  Write-Output "changed=no comment='WebPageTest already installed.'"
} Else {
  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile($URL,$ZipFile)
  Expand-ZIPFile -File $ZipFile -Destination $InstallDir
  Write-Output "changed=yes comment='WebPageTest installed.'"
}

# launch at startup
$GetTask = Get-ScheduledTask | Where-Object {$_.TaskName -like "wptdriver" }

If ($GetTask) {
  Write-Output "changed=no comment='Task (wptdriver) already scheduled.'"
} Else {
  $A = New-ScheduledTaskAction -Execute "$InstallDir\agent\wptdriver.exe"
  $T = New-ScheduledTaskTrigger -AtLogon -User $Username
  $S = New-ScheduledTaskSettingsSet
  $P = New-ScheduledTaskPrincipal -UserId "$ThisHost\$Username" -LogonType ServiceAccount
  Register-ScheduledTask -TaskName "wptdriver" -Action $A -Trigger $T -Setting $S -Principal $P
  Write-Output "changed=yes comment='Task (wptdriver) scheduled.'"
}

$GetTask = Get-ScheduledTask | Where-Object {$_.TaskName -like "urlBlast" }

If ($GetTask) {
  Write-Output "changed=no comment='Task (urlBlast) already scheduled.'"
} Else {
  $A = New-ScheduledTaskAction -Execute "$InstallDir\agent\urlBlast.exe"
  $T = New-ScheduledTaskTrigger -AtLogon -User $Username
  $S = New-ScheduledTaskSettingsSet
  $P = New-ScheduledTaskPrincipal -UserId "$ThisHost\$Username" -LogonType ServiceAccount
  Register-ScheduledTask -TaskName "urlBlast" -Action $A -Trigger $T -Setting $S -Principal $P
  Write-Output "changed=yes comment='Task (urlBlast) scheduled.'"
}

# create WPTdriver.ini file
$wptdriver = @"
[WebPagetest]
url=http://wpt.fasterize.com/
location=frz_eu_paris_wptdriver
browser=chrome,Firefox,IE_10,Safari,chrome_adblock
Time Limit=60
key=fasterizesecretkey
;Automatically install and update support software (Flash, Silverlight, etc)
software=http://www.webpagetest.org/installers/software.dat

[chrome]
exe="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
options='--load-extension="%WPTDIR%\extension" --user-data-dir="%PROFILE%" --no-proxy-server'
installer=http://www.webpagetest.org/installers/browsers/chrome.dat

[chrome_adblock]
exe="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
options='--load-extension="%WPTDIR%\extension,C:\Users\Administrator\Desktop\extensions\adblock" --user-data-dir="%PROFILE%" --no-proxy-server'
installer=http://www.webpagetest.org/installers/browsers/chrome.dat


[Firefox]
exe="C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
options='-profile "%PROFILE%" -no-remote'
installer=http://www.webpagetest.org/installers/browsers/firefox.dat
template=firefox

[Safari]
exe="C:\Program Files (x86)\Safari\Safari.exe"

[IE_10]
exe="C:\Program Files (x86)\Internet Explorer\iexplore.exe"
"@
$wptdriver -replace "`n", "`r`n" | Out-File -FilePath "$InstallDir\agent\wptdriver.ini"

$urlBlast = @"
[Configuration]
Startup Delay=30
Log File=c:\webpagetest\urlblast
Timeout=120
use current account=1

; Where to get work from
Url Files Url=http://wpt.fasterize.com/work/
Location=IE
Location Key=fasterizesecretkey
"@
$urlBlast -replace "`n", "`r`n" | Out-File -FilePath "$InstallDir\agent\urlBlast.ini"

# install dummynet driver
$mindinstURL = "https://github.com/Linuturk/webpagetest/raw/master/webpagetest/powershell/mindinst.exe"
$mindinstFile = "$TempDir\mindinst.exe"

Invoke-WebRequest -Uri $mindinstURL -OutFile $mindinstFile

$crtURL = "https://github.com/Linuturk/webpagetest/raw/master/webpagetest/powershell/WPOFoundation.cer"
$crtFile = "$TempDir\WPOFoundation.cer"

Invoke-WebRequest -Uri $crtURL -OutFile $crtFile

$testsigning = bcdedit | Select-String -pattern "testsigning             Yes"

if ($testsigning) {
  Write-Output "changed=no comment='Test Signing Already Enabled.'"
} Else {
  bcdedit /set TESTSIGNING ON
  Write-Output "changed=yes comment='Test Signing Enabled.'"
}

Import-Certificate -FilePath $TempDir\WPOFoundation.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
cd $TempDir
.\mindinst.exe $InstallDir\agent\dummynet\64bit\netipfw.inf -i -s
Enable-NetAdapterBinding -Name $Interface.Name -DisplayName ipfw+dummynet
Write-Output "changed=yes comment='Enabled ipfw+dummynet binding.'"

bcdedit /set TESTSIGNING OFF
