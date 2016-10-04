# Deployment of an Webpagetest agent

- launch the server in rescue mode
- connect to the server through SSH


## Download the script `deploy-WebpagetestAgent.ps1`

Update the following lines :

```powersheel
[String]$wpt_password = "p@ssword",
[String]$wpt_url = "http://www.webpagetest.com/",
[String]$wpt_location = "wpt_location",
[String]$wpt_key = "wpt_key",
[String]$windows_licenceKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
```

Run the script *as Administrator*.


## Ref :
https://github.com/Linuturk/webpagetest
https://github.com/rackspace-orchestration-templates/webpagetest/
