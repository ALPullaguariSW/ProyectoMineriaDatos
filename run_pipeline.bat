@echo off
echo ===================================================
echo   Data Mining for Secure Software Development
echo   Running Full SEMMA Pipeline & Tests
echo ===================================================

echo.
echo [1/7] Running Unit & Robustness Tests...
set PYTHONPATH=src
python -m pytest tests/test_pipeline.py tests/test_robustness.py
if %errorlevel% neq 0 (
    echo [ERROR] Tests failed!
    exit /b %errorlevel%
)

echo.
echo [2/7] Loading Data (Sample)...
python src/data_loader.py

echo.
echo [3/7] Exploratory Data Analysis (Explore)...
python src/eda.py

echo.
echo [4/7] Preprocessing & Feature Engineering (Modify)...
REM This is implicitly done in training, but we can run it if needed.
REM python src/preprocessing.py

echo.
echo [5/7] Training Models with Grid Search (Model)...
python src/train_model.py

echo.
echo [6/7] Evaluating & Explaining (Assess & Explain)...
python src/evaluate.py
python src/explain.py

echo.
echo [7/7] Monitoring for Drift (Monitor)...
python src/monitor.py

echo.
echo ===================================================
echo   Pipeline Completed Successfully!
echo   Check 'reports/figures' for generated plots.
echo ===================================================
pause
