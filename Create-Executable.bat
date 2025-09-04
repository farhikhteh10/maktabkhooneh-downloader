@echo off
chcp 65001 > nul
cls

echo.
echo  =======================================================
echo  ==    Maktabkhooneh Downloader Executable Builder    ==
echo  =======================================================
echo.
echo  This script will automatically package your Node.js downloader.
echo.

:: Step 1: Check for Node.js
echo [1/5] Checking for Node.js installation...
node -v > nul 2> nul
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: Node.js is not installed or not in PATH.
    echo  Please install it from https://nodejs.org and try again.
    echo.
    pause
    exit
)
echo  OK. Node.js found.
echo.

:: Step 2: Check for downloader.js
echo [2/5] Looking for downloader.js script...
if not exist "downloader.js" (
    echo.
    echo  ERROR: downloader.js file not found.
    echo  Please make sure this .bat file is in the same folder as downloader.js.
    echo.
    pause
    exit
)
echo  OK. downloader.js found.
echo.

:: Step 3: Create package.json
echo [3/5] Creating configuration file (package.json)...
(
    echo {
    echo   "name": "maktab-downloader",
    echo   "version": "1.0.0",
    echo   "description": "Maktabkhooneh Course Downloader",
    echo   "main": "downloader.js",
    echo   "bin": "downloader.js",
    echo   "dependencies": {
    echo     "node-fetch": "^2.6.7"
    echo   },
    echo   "pkg": {
    echo     "targets": [ "node18-win-x64" ],
    echo     "outputPath": "dist"
    echo   }
    echo }
) > package.json
echo  OK. package.json created.
echo.

:: Step 4: Install dependencies and run pkg
echo [4/5] Installing dependencies and building the executable...
echo  This may take a few minutes, please be patient.
echo.
call npm install > nul 2> nul
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: npm install failed. Check your internet connection.
    echo.
    pause
    exit
)
call pkg .
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: pkg failed to build the executable.
    echo.
    pause
    exit
)
echo.

:: Step 5: Cleanup
echo [5/5] Cleaning up temporary files...
del package.json > nul 2> nul
del package-lock.json > nul 2> nul
rmdir /s /q node_modules > nul 2> nul
echo  OK. Cleanup complete.
echo.

echo  =======================================================
echo  ==         SUCCESS! Your file is ready.              ==
echo  =======================================================
echo.
echo  The executable file downloader.exe is located in the 'dist' folder.
echo.
pause