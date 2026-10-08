@echo off
title Aegis Sentinel Security System
echo Starting Aegis Sentinel...
set "PY_PATH=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if exist "%PY_PATH%" (
    "%PY_PATH%" main.py %*
) else (
    python main.py %*
)
pause
