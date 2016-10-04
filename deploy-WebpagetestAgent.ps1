# Deployment of Web Page Test
Function Deploy-WebPagetest(){
    [CmdletBinding()]
    Param(
        [String]$DomainName = "localhost",
        [String]$Logfile = "C:\Windows\Temp\Deploy-WebPageTest.log",
        [String]$wpt_host =  $env:COMPUTERNAME,
        [String]$wpt_user = "Administrator",
        [String]$driver_installer_file = "mindinst.exe",
        [String]$driver_installer_cert_file = "WPOFoundation.cer",
        [String]$wpt_agent_dir = "C:\webpagetest",
        [String]$wpt_temp_dir = "C:\wpt-temp",
        [String]$wpt_password = "p@ssword",
        [String]$wpt_url = "http://www.webpagetest.com/",
        [String]$wpt_location = "wpt_location",
        [String]$wpt_key = "wpt_key",
        [String]$windows_licenceKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    )
    # Create Log File
    if (!( Test-Path $Logfile)){
        New-Item -Path "C:\Windows\Temp\Deploy-WebPageTest.log" -ItemType file
    }

    Function Write-Log{
        Param ([string]$logstring)
        Add-content $Logfile -value $logstring
        Write-Output $logstring
    }

    # External Dependencies
    $wpt_zip_url =  "https://github.com/WPO-Foundation/webpagetest/releases/download/WebPageTest-2.19/webpagetest_2.19.zip"
    $wpt_zip_file = "webpagetest_2.19.zip"

    # Github Dependencies
    $driver_installer_cert_url = "https://github.com/fasterize/webpagetest-installation/raw/master/files/WPOFoundation.cer"
    $driver_installer_url = "https://raw.githubusercontent.com/fasterize/webpagetest-installation/master/files/mindinst.exe"
    $wpt_urlBlast_ini = "https://raw.githubusercontent.com/fasterize/webpagetest-installation/master/files/urlBlast.ini"
    $wpt_wptdriver_ini = "https://raw.githubusercontent.com/fasterize/webpagetest-installation/master/files/wptdriver.ini"

    # Scripts
    $DefaultUserNameURL = "https://raw.githubusercontent.com/fasterize/webpagetest-installation/master/files/DefaultUserName.ps1"
    $FirstRebootURL = "https://raw.githubusercontent.com/fasterize/webpagetest-installation/master/files/FirstReboot.ps1"

    $DnsResolver1 = "8.8.8.8"
    $DnsResolver2 = "8.8.4.4"
    $lang = "fr-FR"

    function Set-WptFolders(){
        $wpt_folders = @($wpt_agent_dir,$wpt_temp_dir)
        foreach ($wpt_folder in $wpt_folders){
            New-Item $wpt_folder -type directory -Force *>> $Logfile
        }
    }
    function Download-File ($url, $localpath, $filename){
        if(!(Test-Path -Path $localpath)){
            New-Item $localpath -type directory *>> $Logfile
        }
        Write-Log "[$(Get-Date)] Downloading $filename"
        $webclient = New-Object System.Net.WebClient;
        $webclient.Headers.Add("user-agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")
        $webclient.DownloadFile($url, $localpath + "\" + $filename)
    }
    function Unzip-File($fileName, $sourcePath, $destinationPath){
        Write-Log "[$(Get-Date)] Unzipping $filename to $destinationPath"
        $shell = new-object -com shell.application
        if (!(Test-Path "$sourcePath\$fileName")){
            throw "$sourcePath\$fileName does not exist"
        }
        New-Item -ItemType Directory -Force -Path $destinationPath -WarningAction SilentlyContinue *>> $Logfile
        $shell.namespace($destinationPath).copyhere($shell.namespace("$sourcePath\$fileName").items()) *>> $Logfile
    }

    function Set-WindowsLicense ($LicenseKey) {
        Write-Log "[$(Get-Date)] Set Windows License."
        DISM /online /Set-Edition:ServerStandard /ProductKey:$LicenseKey /AcceptEula
    }

    function Activate-Windows-Update () {
        Write-Log "[$(Get-Date)] Activate Windows Update."
        $AUSettigns = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
        $AUSettigns.NotificationLevel = 4
        $AUSettigns.Save()
    }

    function Replace-String ($filePath, $stringToReplace, $replaceWith){
        (get-content $filePath) | foreach-object {$_ -replace $stringToReplace, $replaceWith} | set-content $filePath *>> $Logfile
    }

    function Set-Keyboard ($Lang) {
        Write-Log "[$(Get-Date)] Set Keyboard to $lang."
        Set-WinUserLanguageList -LanguageList $Lang
    }

    function ExtendPartition () {
        Write-Log "[$(Get-Date)] Extend partition of drive C."
        $MaxSize = (Get-PartitionSupportedSize -DriveLetter c).sizeMax
        Resize-Partition -DriveLetter c -Size $MaxSize
    }

    function Disable-MouseShadow () {
        Write-Log "[$(Get-Date)] Disable mouse shadow for RPC program"
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 00000003
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "CursorShadow" -Value 00000000
        Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name 'UserPreferencesMask' -Value ([byte[]](0x9E,0x1E,0x07,0x80,0x12,0x00,0x00,0x00))
    }

    function Set-DnsResolver ($Resolver1, $Resolver2) {
        Write-Log "[$(Get-Date)] Set DNS resolver to $resolver1 and $resolver2"
        netsh interface ip add dns name="Ethernet" addr="$Resolver1" index=1
        netsh interface ip add dns name="Ethernet" addr="$Resolver2" index=2
    }

    function Set-WebPageTestUser ($Username, $Password){
        $Exists = [ADSI]::Exists("WinNT://./$Username")
        if ($Exists) {
            Write-Log "[$(Get-Date)] $Username user already exists."
        } Else {
            net user /add $Username *>> $Logfile
            net localgroup Administrators /add $Username *>> $Logfile
            Write-Log "[$(Get-Date)] $Username created."
        }
        $user = [ADSI]("WinNT://./$Username")
        $user.SetPassword($Password)
        $user.SetInfo()
        Write-Log "[$(Get-Date)] $Password updated."
    }
    function Set-AutoLogon ($Username, $Password){
        $LogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $CurrentVal = Get-ItemProperty -Path $LogonPath -Name AutoAdminLogon
        If ($CurrentVal.AutoAdminLogon -eq 1) {
            $CurrentUser = Get-ItemProperty -Path $LogonPath -Name DefaultUserName
            $CurrentPass = Get-ItemProperty -Path $LogonPath -Name DefaultPassword
            If ($CurrentUser.DefaultUserName -ne $Username -Or $CurrentPass.DefaultPassword -ne $Password) {
                Set-ItemProperty -Path $LogonPath -Name DefaultUserName -Value $Username
                Set-ItemProperty -Path $LogonPath -Name DefaultPassword -Value $Password
                Write-Log "[$(Get-Date)] Credentials Updated."
            }Else {
                Write-Log "[$(Get-Date)] AutoLogon already enabled."
            }
        }Else {
            Set-ItemProperty -Path $LogonPath -Name AutoAdminLogon -Value 1
            New-ItemProperty -Path $LogonPath -Name DefaultUserName -Value $Username
            New-ItemProperty -Path $LogonPath -Name DefaultPassword -Value $Password
            Write-Log "[$(Get-Date)] AutoLogon enabled."
        }
    }
    function Set-DisableServerManager (){
        $CurrentState = Get-ScheduledTask -TaskName "ServerManager"
        If ($CurrentState.State -eq "Ready") {
            Get-ScheduledTask -TaskName "ServerManager" | Disable-ScheduledTask *>> $Logfile
            Write-Log "[$(Get-Date)] Server Manager disabled at logon."
        } Else {
            Write-Log "[$(Get-Date)] Server Manager already disabled at logon."
        }
    }
    function Set-MonitorTimeout (){
        $CurrentVal = POWERCFG /QUERY SCHEME_BALANCED SUB_VIDEO VIDEOIDLE | Select-String -pattern "Current AC Power Setting Index:"
        If ($CurrentVal -like "*0x00000000*") {
            Write-Log "[$(Get-Date)] Display Timeout already set to Never."
        } Else {
            POWERCFG /CHANGE -monitor-timeout-ac 0
            Write-Log "[$(Get-Date)] Display Timeout set to Never."
        }
    }
    function Set-DisableScreensaver (){
        $Path = 'HKCU:\Control Panel\Desktop'
        Try {
          $CurrentVal = Get-ItemProperty -Path $Path -Name ScreenSaveActive
          Write-Log "[$(Get-Date)] $CurrentVal"
        } Catch {
          $CurrentVal = False
        } Finally {
          if ($CurrentVal.ScreenSaveActive -ne 0) {
            Set-ItemProperty -Path $Path -Name ScreenSaveActive -Value 0 *>> $Logfile
            Write-Log "[$(Get-Date)] Screensaver Disabled."
          } Else {
            Write-Log "[$(Get-Date)] Screensaver Already Disabled."
          }
        }
    }
    function Set-DisableUAC (){
        $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $CurrentVal = Get-ItemProperty -Path $Path -Name ConsentPromptBehaviorAdmin
        if ($CurrentVal.ConsentPromptBehaviorAdmin -ne 00000000) {
            Set-ItemProperty -Path $Path -Name "ConsentPromptBehaviorAdmin" -Value 00000000 *>> $Logfile
            Write-Log "[$(Get-Date)] UAC Disabled."
        } Else {
            Write-Log "[$(Get-Date)] UAC Already Disabled."
        }
    }
    function Set-DisableIESecurity (){
        $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
        $CurrentVal = Get-ItemProperty -Path $AdminKey -Name "IsInstalled"
        if ($CurrentVal.IsInstalled -ne 0) {
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 *>> $Logfile
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 *>> $Logfile
            Write-Log "[$(Get-Date)] IE ESC Disabled."
        } Else {
            Write-Log "[$(Get-Date)] IE ESC Already Disabled."
        }
    }
    function Set-StableClock (){
        $useplatformclock = bcdedit | Select-String -pattern "useplatformclock        Yes"
        if ($useplatformclock) {
            Write-Log "[$(Get-Date)] Platform Clock Already Enabled."
        } Else {
            bcdedit /set  useplatformclock true *>> $Logfile
            Write-Log "[$(Get-Date)] Platform Clock Enabled."
        }
    }
    function Set-DisableShutdownTracker (){
        $Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability'
        Try {
            $CurrentVal = Get-ItemProperty -Path $Path -Name ShutdownReasonUI -ErrorAction SilentlyContinue
            Write-Log "[$(Get-Date)] $CurrentVal"
        } Catch {
            $CurrentVal = False
        } Finally {
            if ($CurrentVal.ShutdownReasonUI -ne 0) {
                New-ItemProperty -Path $Path -Name ShutdownReasonUI -Value 0
                Write-Log "[$(Get-Date)] Shutdown Tracker Disabled."
            }Else{
                Write-Log "[$(Get-Date)] Shutdown Tracker Already Disabled."
            }
        }
    }
    Function Set-WebPageTestInstall ($tempDir,$AgentDir,$wwwDir){
        Copy-Item -Path $AgentDir\agent\* -Destination $wpt_agent_dir -Recurse -Force *>> $Logfile
    }

    function Set-InstallDummyNet ($InstallDir){
        Download-File -url $driver_installer_url -localpath $InstallDir -filename $driver_installer_file
        Download-File -url $driver_installer_cert_url -localpath $InstallDir -filename $driver_installer_cert_file
        $testsigning = bcdedit | Select-String -pattern "testsigning Yes"
        if ($testsigning) {
            Write-Log "[$(Get-Date)] Test Signing Already Enabled."
        } Else {
            bcdedit /set TESTSIGNING ON *>> $Logfile
            Write-Log "[$(Get-Date)] Test Signing Enabled."

            $dummynet = Get-NetAdapterBinding -Name Ethernet

            If ($dummynet.DisplayName -match "dummynet") {
              Write-Log "[$(Get-Date)] DummyNet already enabled."
            } Else {
              Write-Log "[$(Get-Date)] Installation of DummyNet."
              Import-Certificate -FilePath $InstallDir\WPOFoundation.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
              cd $InstallDir
              .\mindinst.exe $InstallDir\dummynet\64bit\netipfw.inf -i -s
              Enable-NetAdapterBinding -Name Ethernet -DisplayName ipfw+dummynet
            }

        }
    }
    function Set-WebPageTestScheduledTask ($ThisHost, $User,$InstallDir){
        $GetTask = Get-ScheduledTask
        if ($GetTask.TaskName -match "wptdriver") {
            Write-Log "[$(Get-Date)] Task (wptdriver) already scheduled."
        } Else {
            $A = New-ScheduledTaskAction -Execute "$InstallDir\wptdriver.exe"
            $T = New-ScheduledTaskTrigger -AtLogon -User $User
            $S = New-ScheduledTaskSettingsSet
            $P = New-ScheduledTaskPrincipal -UserId "$ThisHost\$User" -LogonType ServiceAccount
            Register-ScheduledTask -TaskName "wptdriver" -Action $A -Trigger $T -Setting $S -Principal $P *>> $Logfile
            Write-Log "[$(Get-Date)] Task (wptdriver) scheduled."
        }
        $GetTask = Get-ScheduledTask
        if ($GetTask.TaskName -match "urlBlast") {
            Write-Log "[$(Get-Date)] Task (urlBlast) already scheduled."
        } Else {
            $A = New-ScheduledTaskAction -Execute "$InstallDir\urlBlast.exe"
            $T = New-ScheduledTaskTrigger -AtLogon -User $User
            $S = New-ScheduledTaskSettingsSet
            $P = New-ScheduledTaskPrincipal -UserId "$ThisHost\$User" -LogonType ServiceAccount
            Register-ScheduledTask -TaskName "urlBlast" -Action $A -Trigger $T -Setting $S -Principal $P *>> $Logfile
            Write-Log "[$(Get-Date)] Task (urlBlast) scheduled."
        }
    }
    function Set-ScheduleDefaultUserName ($ThisHost, $User, $Password, $InstallDir) {
        Invoke-WebRequest $DefaultUserNameURL -OutFile "$InstallDir\DefaultUserName.ps1" *>> $Logfile
        Replace-String -filePath "$InstallDir\DefaultUserName.ps1" -stringToReplace "%%USERNAME%%" -replaceWith $User
        $A = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File $InstallDir\DefaultUserName.ps1"
        $T = New-ScheduledTaskTrigger -AtStartup
        $S = New-ScheduledTaskSettingsSet
        $D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
        Register-ScheduledTask -TaskName "DefaultUserName Fix" -InputObject $D -User $User -Password $Password *>> $Logfile
    }

    function Clean-Deployment{
        # Remove Automation initial firewall rule opener
        if((Test-Path -Path 'C:\Cloud-Automation')){
            Remove-Item -Path 'C:\Cloud-Automation' -Recurse *>> $Logfile
        }

        # Schedule Task to remove the Psexec firewall rule
        $DeletePsexec = {
            Remove-Item $MyINvocation.InvocationName
            $find_rule = netsh advfirewall firewall show rule "PSexec Port"
            if ($find_rule -notcontains 'No rules match the specified criteria.') {
                Write-Host "Deleting firewall rule"
                netsh advfirewall firewall delete rule name="PSexec Port" *>> $Logfile
            }
        }
        $Cleaner = "C:\Windows\Temp\cleanup.ps1"
        Set-Content $Cleaner $DeletePsexec
        $ST_Username = "autoadmin"
        net user /add $ST_Username $FtpPassword *>> $Logfile
        net localgroup administrators $ST_Username /add *>> $Logfile
        $ST_Exec = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $ST_Arg = "-NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy ByPass C:\Windows\Temp\cleanup.ps1"
        $ST_A_Deploy_Cleaner = New-ScheduledTaskAction -Execute $ST_Exec -Argument $ST_Arg
        $ST_T_Deploy_Cleaner = New-ScheduledTaskTrigger -Once -At ((Get-date).AddMinutes(2))
        $ST_S_Deploy_Cleaner = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -WakeToRun -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances Parallel
        Register-ScheduledTask -TaskName "Clean Automation" -TaskPath \ -RunLevel Highest -Action $ST_A_Deploy_Cleaner -Trigger $ST_T_Deploy_Cleaner -Settings $ST_S_Deploy_Cleaner -User $ST_Username -Password $FtpPassword *>> $Logfile

    }
    function Set-WptConfig ($Location, $Url, $Key){
        Download-File -url $wpt_urlBlast_ini -localpath $wpt_agent_dir -filename "urlBlast.ini"
        Replace-String -filePath "$wpt_agent_dir\urlBlast.ini" -stringToReplace "%%URL%%" -replaceWith $Url
        Replace-String -filePath "$wpt_agent_dir\urlBlast.ini" -stringToReplace "%%KEY%%" -replaceWith $Key

        Download-File -url $wpt_wptdriver_ini -localpath $wpt_agent_dir -filename "wptdriver.ini"
        Replace-String -filePath "$wpt_agent_dir\wptdriver.ini" -stringToReplace "%%URL%%" -replaceWith $Url
        Replace-String -filePath "$wpt_agent_dir\wptdriver.ini" -stringToReplace "%%KEY%%" -replaceWith $Key
        Replace-String -filePath "$wpt_agent_dir\wptdriver.ini" -stringToReplace "%%LOCATION%%" -replaceWith $Location
    }
    function Set-ClosePort445 (){
        $CurrentVal = Get-NetFirewallRule
        if ($CurrentVal.InstanceID -match "PSexec Port" -and $CurrentVal.Enabled -eq "true") {
            Disable-NetFirewallRule -Name "PSexec Port" *>> $Logfile
            Write-Log "[$(Get-Date)] Port PSexec Port Disabled."
        } Elseif($CurrentVal.InstanceID -match "PSexec Port" -and $CurrentVal.Enabled -eq "false"){
            Write-Log "[$(Get-Date)] Port PSexec Port Already Disabled."
        }Else {
            Write-Log "[$(Get-Date)] Port PSexec Port rules does not exist."
        }
    }
    function Disable-FindNetDevices(){
        Set-Service fdPHost -StartupType Manual
        Stop-Service fdPHost -force
    }

    # => Main
    Set-WindowsLicense -LicenseKey $windows_licenseKey
    Activate-Windows-Update
    Set-Keyboard -Lang $lang
    ExtendPartition
    Set-DnsResolver -Resolver1 $DnsResolver1 -Resolver2 $DnsResolver2
    Disable-MouseShadow
    Set-WebPageTestUser -Username $wpt_user -Password $wpt_password
    Set-AutoLogon -Username $wpt_user -Password $wpt_password
    Set-DisableServerManager
    Set-MonitorTimeout
    Set-DisableScreensaver
    Set-DisableUAC
    Set-DisableIESecurity
    Set-StableClock
    Set-DisableShutdownTracker
    Set-WptFolders
    Download-File -url $wpt_zip_url -localpath $wpt_temp_dir -filename $wpt_zip_file
    Download-File -url $driver_installer_url -localpath $wpt_agent_dir -filename $driver_installer_file
    Download-File -url $driver_installer_cert_url -localpath $wpt_temp_dir -filename $driver_installer_cert_file
    Unzip-File -fileName $wpt_zip_file -sourcePath $wpt_temp_dir -destinationPath $wpt_agent_dir
    Set-WebPageTestInstall -tempDir $wpt_temp_dir -AgentDir $wpt_agent_dir
    Set-InstallDummyNet -InstallDir $wpt_agent_dir
    Set-WebPageTestScheduledTask -ThisHost $wpt_host -User $wpt_user -InstallDir $wpt_agent_dir
    Set-ScheduleDefaultUserName -ThisHost $wpt_host -User $wpt_user -Password $wpt_password -InstallDir $wpt_agent_dir
    Set-WptConfig -Location $wpt_location -Url $wpt_url -Key $wpt_key
    Disable-FindNetDevices
    Set-ClosePort445

}

# MAIN : Deploy Web Pagge Test
Deploy-WebPagetest
#Deploy-WebPagetest -DomainName "%wptdomain%" -wpt_user "%wptusername%" -wpt_password "%wptpassword%"
