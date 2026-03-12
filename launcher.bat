@echo off
chcp 65001 >nul
echo ========================================
echo F5 UCS 配置分析工具 - 启动器
echo ========================================
echo.

cd /d "%~dp0"

:menu
cls
echo ========================================
echo F5 UCS 配置分析工具
echo ========================================
echo.
echo 请选择运行方式:
echo.
echo  [1] Web 界面方式 (推荐)
echo      - 浏览器访问 http://localhost:5000
echo      - 支持拖拽上传
echo      - 实时查看进度
echo.
echo  [2] 命令行方式
echo      - 适合批量处理
echo      - 需要指定文件路径
echo.
echo  [3] 安装/修复依赖
echo      - 首次使用或依赖出错时运行
echo.
echo  [4] 清理临时文件
echo      - 删除上传文件和分析结果
echo.
echo  [0] 退出
echo.
echo ========================================
set /p choice="请输入选项 (0-4): "

if "%choice%"=="1" goto web
if "%choice%"=="2" goto cli
if "%choice%"=="3" goto setup
if "%choice%"=="4" goto cleanup
if "%choice%"=="0" goto exit
goto menu

:web
cls
echo 正在启动 Web 服务...
echo.
echo 启动后请访问: http://localhost:5000
echo.
echo 按 Ctrl+C 停止服务
echo.
.\venv\Scripts\python.exe web_server.py
pause
goto menu

:cli
cls
echo ========================================
echo 命令行方式 - F5 UCS 分析
echo ========================================
echo.
set /p ucsfile="请输入 UCS 文件路径: "
set /p output="请输入输出目录 (直接回车使用默认): "

if "%output%"=="" set output=./analysis_output

echo.
echo 开始分析...
echo 文件: %ucsfile%
echo 输出: %output%
echo.

.\venv\Scripts\python.exe f5_ucs_analyzer.py -u "%ucsfile%" -o "%output%"

echo.
pause
goto menu

:setup
cls
echo ========================================
echo 安装/修复依赖
echo ========================================
echo.

if not exist "venv" (
    echo 创建虚拟环境...
    python -m venv venv
)

echo 安装依赖包...
.\venv\Scripts\pip.exe install pandas openpyxl flask flask-cors werkzeug

echo.
echo 安装完成!
pause
goto menu

:cleanup
cls
echo ========================================
echo 清理临时文件
echo ========================================
echo.

echo 正在清理 uploads 目录...
if exist "uploads" (
    for %%f in (uploads\*) do del /q "%%f"
    echo uploads 目录已清理
)

echo 正在清理 results 目录...
if exist "results" (
    for /d %%d in (results\*) do rd /s /q "%%d"
    echo results 目录已清理
)

echo.
echo 清理完成!
pause
goto menu

:exit
exit /b 0
