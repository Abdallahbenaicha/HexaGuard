@echo off
setlocal
cd /d "%~dp0"

echo [SecurAx] Cleaning previous server on 5000...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
  echo [SecurAx] Killing PID %%P
  taskkill /PID %%P /F >nul 2>nul
)

echo [SecurAx] Activating venv...
call E:\PFE\.venv\Scripts\activate.bat

echo [SecurAx] Starting app on http://127.0.0.1:5000
start "" http://127.0.0.1:5000
python app.py
endlocal

