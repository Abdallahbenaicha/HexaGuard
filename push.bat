@echo off
cd /d "e:\PFE\concept\finalpfe-master\Nouveau dossier\finalpfe-master"
git config http.postBuffer 524288000
git config http.lowSpeedLimit 0
git config http.lowSpeedTime 999999
git push origin main --force
echo EXIT CODE: %errorlevel%
pause
