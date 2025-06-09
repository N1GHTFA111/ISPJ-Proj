@echo off
REM Activate the virtual environment (adjust the path accordingly)
call venv\Scripts\activate

REM Migrate Sentinel_api
cd Sentinel_api
set FLASK_APP=app
set FLASK_ENV=development

REM Initialize migration
flask db init

REM Generate migration
flask db migrate -m "Sentinel_api migration message"

REM Apply migration
flask db upgrade

cd ..

REM Migrate Bank_app
cd Bank_app
set FLASK_APP=app
set FLASK_ENV=development

REM Initialize migration
flask db init

REM Generate migration
flask db migrate -m "Bank_app migration message"

REM Apply migration
flask db upgrade

cd ..

pause
