@echo off
title Aegis Sentinel - Interactive Security Console
set "PY_PATH=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if exist "%PY_PATH%" (
    "%PY_PATH%" main.py --cli
) else (
    python main.py --cli
)
pause
