
@echo off

set directory=%~dp0
cd /d %directory%

if %time:~0,2% leq 9 (set hour=0%time:~1,1%) else (set hour=%time:~0,2%) 

set report="report_nj_ok_result_%date:~,4%%date:~5,2%%date:~8,2%_%hour%%time:~3,2%%time:~6,2%.html"
set log_dir="log\Log_nj_ok_%date:~,4%%date:~5,2%%date:~8,2%_%hour%%time:~3,2%%time:~6,2%"
if not exist %log_dir% (
 md %log_dir%
) 

set cmdLine= pybot -V SystemTesting-nj\Variable\Variables.py -d %log_dir% -i ok SystemTesting-nj
call %cmdLine%

set cmdLine= python report_script_py\MyRFreport.py %log_dir% %report%
call %cmdLine%

exit 0

 注意：这里不能有pause，否则一个实例在运行，另一个实例就不能启动，可以进入“控制面板”》“管理工具”》“任务计划程序”》点击事件右键属性，修改成“可以并行执行”。此时有了pause，也能两个实例并行运行。

--------------------------------------------------------------------------------

 

ok_time.bat:

 

echo on
set CUR_DIR=%~dp0

%SystemDrive%
cd %windir%\tasks\
if exist %NAME%.job del %NAME%.job

cd /d %CUR_DIR%

schtasks /create /tn nj_ok /tr %CUR_DIR%\nj_ok_test.bat /sc hourly /mo 4 /st 18:59:00

pause

exit 0

 

--------------------------------------------------------------------------------

 

schtasks:

schtasks /create /tn TaskName /tr TaskRun /sc schedule [/mo modifier][/d day][/m month[,month...][/i IdleTime][/st StartTime][/sd StartDate][/ed EndDate][/s computer[/u [domain\]user /p password]][/ru {[Domain\]User|"System"} [/rp Password]]/?
