@echo off
setlocal
echo [SecurAx] Stopping server on port 5000...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
  echo [SecurAx] Killing PID %%P
  taskkill /PID %%P /F >nul 2>nul
)
echo [SecurAx] Done.
endlocal

