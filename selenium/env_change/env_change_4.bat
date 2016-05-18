set directory=%~dp0
cd /d %directory%

set dns4=21
python gvc_oper.py %dns4%

netsh int ip set dns localhost static 192.168.121.%dns4%
ipconfig /flushdns
ipconfig /all

pause