rem set directory=%~dp0
rem cd /d %directory%

rem set dns4=4
rem python correct_dns.py %dns4%

netsh int ip set dns localhost static 192.168.121.120
ipconfig /flushdns
ipconfig /all

pause