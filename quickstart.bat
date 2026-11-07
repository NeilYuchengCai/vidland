@echo off
chcp 65001 >nul 2>&1
title Vidland Chancellery - Quick Console
cd /d "%~dp0"
python "%~dp0quickstart.py" %*
if errorlevel 1 (
  echo.
  echo Python returned an error. Make sure Python 3 is installed and on PATH.
  pause
)
