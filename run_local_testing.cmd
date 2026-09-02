@echo off
setlocal
set "ROOT=%~dp0"
set "PROXYPILOT_DATA_DIR=%ROOT%runtime-local"
set "DB_ENGINE=sqlite"
set "DEBUG=true"
set "LOCAL_TESTING_MODE=true"
set "DJANGO_SECRET_KEY=local-testing-only-change-me"
set "CONFIG_ENCRYPTION_SECRET=local-testing-encryption-only-change-me"
set "ALLOWED_HOSTS=127.0.0.1,localhost"
set "CSRF_TRUSTED_ORIGINS=http://127.0.0.1:8765"
set "TRUST_APP_REPORTED_IPV4=true"
set "REQUIRE_REPORTED_IP_MATCH=false"
set "CELERY_TASK_ALWAYS_EAGER=true"
set "LOCAL_TESTING_CONFIG=%ROOT%local_testing_config.json"
set "LOCAL_PROXY_ROOT=%ROOT%local_proxy"

if not exist "%ROOT%local_testing_config.json" (
  copy /Y "%ROOT%local_testing_config.example.json" "%ROOT%local_testing_config.json" >nul
  echo Fill local_testing_config.json before starting the local API.
  pause
  exit /b 1
)

call "%ROOT%.venv\Scripts\activate.bat"
python "%ROOT%manage.py" migrate
if errorlevel 1 exit /b 1
python "%ROOT%setup_local_testing.py"
if errorlevel 1 exit /b 1

echo Local control API running at http://127.0.0.1:8765
python "%ROOT%manage.py" runserver 127.0.0.1:8765
endlocal
