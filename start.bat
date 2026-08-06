@echo off
echo Starting MCP Security Copilot v2.0 - Enterprise Edition
echo.

echo ========================================
echo Starting Backend Server
echo ========================================
cd backend
set PYTHONPATH=%CD%
start "Backend Server" cmd /k "uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
echo Backend server starting on http://localhost:8000
echo.

echo ========================================
echo Starting Frontend Server
echo ========================================
cd ..\frontend
start "Frontend Server" cmd /k "npx vite --host 0.0.0.0 --port 5173"
echo Frontend server starting on http://localhost:5173 (may auto-adjust if port is in use)
echo.

echo ========================================
echo Servers Starting...
echo ========================================
echo.
echo Backend API: http://localhost:8000
echo Frontend: http://localhost:5173 (check actual port in frontend window)
echo API Documentation: http://localhost:8000/api/docs
echo Health Check: http://localhost:8000/health
echo.
echo Default Admin Credentials:
echo Username: admin
echo Password: admin123
echo.
echo Note: Frontend may start on a different port if 5173 is in use.
echo Check the frontend window for the actual URL.
echo.
echo Press any key to continue (then open the frontend URL manually)...
pause > nul

echo.
echo Servers are running in separate windows.
echo Close those windows to stop the servers.
pause