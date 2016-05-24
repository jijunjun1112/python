@echo on

set directory=%~dp0
cd /d %directory%

if %time:~0,2% leq 9 (set hour=0%time:~1,1%) else (set hour=%time:~0,2%) 

set log_dir=log\Log_ok_%date:~,4%%date:~5,2%%date:~8,2%_%hour%%time:~3,2%%time:~6,2%
if not exist %log_dir% (
 md %log_dir%
) 

set cmdLine= pybot -V config.py -d log/%log_dir% -i ok %directory%
call %cmdLine%

pause
exit 0
