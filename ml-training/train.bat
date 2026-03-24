@echo off
echo ================================================
echo   PhishGuard ML Training Pipeline
echo ================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Install Python 3.10+ first.
    pause
    exit /b 1
)

REM Create venv if needed
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing training dependencies...
pip install -r requirements.txt
echo.

echo ================================================
echo   Step 1: Building Dataset
echo ================================================
echo This fetches phishing and legitimate URL feeds.
echo Depending on network speed, this may take 30-120 seconds.
echo.
python build_dataset.py --limit 25000
if errorlevel 1 (
    echo.
    echo Dataset build failed! Check your internet connection.
    pause
    exit /b 1
)

echo.
echo ================================================
echo   Step 2: Training Model
echo ================================================
echo.
python train_url_model.py
if errorlevel 1 (
    echo.
    echo Training failed!
    pause
    exit /b 1
)

echo.
echo ================================================
echo   All Done!
echo ================================================
echo.
echo Model has been saved to:
echo   ..\extension\models\model.onnx
echo.
echo You can now:
echo   1. Load the extension in Chrome (chrome://extensions)
echo   2. Start the backend: cd ..\backend ^&^& python -m app.main
echo.
pause
