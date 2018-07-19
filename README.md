## Download the script `deploy-WebpagetestAgent.ps1`

Update the following lines :

```powersheel
[String]$wpt_password = "p@ssword",
[String]$wpt_url = "http://www.webpagetest.org/",
[String]$wpt_location = "wpt_location",
[String]$wpt_key = "wpt_key",
[String]$windows_licenseKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
```

## Run the script *as Administrator*.

- Create a shortcut to your Powershell script on your desktop
- Right-click the shortcut and click Properties
- Edit the command `powershell.exe -NoExit -f deploy-WebpagetestAgent.ps1`
- Click the Shortcut tab
- Click Advanced
- Select Run as Administrator

## Pitfull/Post manual task
- the installation of the driver ipfw+dummynet doesn't seem to work. We reinstalled it manually by following this guide : https://www.fasterize.com/en/blog/guide-for-the-installation-of-a-webpagetest-agent-on/
- Launch IE on each server, and click through *Manage Add-on* to enable the Browser Helper Object. Otherwise, your IE tests will fail.

## Ref :
- https://github.com/Linuturk/webpagetest
- https://github.com/rackspace-orchestration-templates/webpagetest/
