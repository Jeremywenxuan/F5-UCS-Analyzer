@echo off
chcp 65001 >nul
echo ========================================
echo F5 UCS 配置分析工具 - Web 服务
echo ========================================
echo.

cd /d "%~dp0"

if not exist "venv" (
    echo 错误: 虚拟环境不存在，请先运行 setup.bat
    pause
    exit /b 1
)

echo 正在启动 Web 服务...
echo.
echo 启动后请访问: http://localhost:5000
echo.
echo 按 Ctrl+C 停止服务
echo ========================================
echo.

.\venv\Scripts\python.exe web_server.py

pause
