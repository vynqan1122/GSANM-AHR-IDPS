@echo off
rem Double-click de bat toan bo AHR-IDPS bang Git Bash.
rem Co the truyen tham so giong start.sh, vi du: start.cmd stop
setlocal
set "GITBASH=%ProgramFiles%\Git\bin\bash.exe"
if not exist "%GITBASH%" set "GITBASH=%ProgramFiles(x86)%\Git\bin\bash.exe"
if not exist "%GITBASH%" set "GITBASH=%LocalAppData%\Programs\Git\bin\bash.exe"
if not exist "%GITBASH%" (
    echo Khong tim thay Git Bash. Cai Git for Windows roi chay lai.
    pause
    exit /b 1
)
"%GITBASH%" "%~dp0start.sh" %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
