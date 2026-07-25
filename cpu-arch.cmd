@echo off

@echo off

echo %PROCESSOR_IDENTIFIER% | findstr /i "AMD" >nul
if %errorlevel% equ 0 (
    set "CPU=AMD"
)

echo %PROCESSOR_IDENTIFIER% | findstr /i "Intel" >nul
if %errorlevel% equ 0 (
    set "CPU=Intel"
)

echo CPU Vendor: %CPU%
pause
