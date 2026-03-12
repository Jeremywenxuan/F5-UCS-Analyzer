@echo off
chcp 65001 >nul
echo ========================================
echo F5 UCS 配置分析工具
echo ========================================
echo.

if "%~1"=="" (
    echo 使用方法: analyze_ucs.bat ^<ucs文件路径^> [输出目录]
    echo.
    echo 示例:
    echo   analyze_ucs.bat C:\backup\config.ucs
    echo   analyze_ucs.bat C:\backup\config.ucs D:\output
    goto :end
)

set UCS_FILE=%~1
set OUTPUT_DIR=%~2

if "%~2"=="" set OUTPUT_DIR=./analysis_output

echo UCS 文件: %UCS_FILE%
echo 输出目录: %OUTPUT_DIR%
echo.

cd /d "%~dp0"
.\venv\Scripts\python.exe f5_ucs_analyzer.py -u "%UCS_FILE%" -o "%OUTPUT_DIR%"

echo.
pause

:end
