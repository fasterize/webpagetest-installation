Start-Sleep -s 60

$InstallDir = "C:\webpagetest"
$dummynet = Get-NetAdapterBinding -Name Ethernet

If ($dummynet.ComponentID -eq "ipfw+dummynet") {
  Write-Output "Already Enabled."
} Else {
  Import-Certificate -FilePath C:\wpt-agent\WPOFoundation.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
  cd $InstallDir
  .\mindinst.exe C:\wpt-agent\dummynet\64bit\netipfw.inf -i -s
  Enable-NetAdapterBinding -Name Ethernet -DisplayName ipfw+dummynet
}
