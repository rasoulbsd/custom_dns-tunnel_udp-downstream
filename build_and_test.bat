@echo off
REM Build and test script for Windows
REM This builds the binaries, then you can test in WSL

echo === Building DNS Tunnel ===
echo.

REM Build release binaries
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

echo.
echo === Build successful! ===
echo.
echo Binaries are in: target\release\
echo   - server.exe
echo   - client.exe
echo.
echo To test in WSL, run:
echo   ./test_comprehensive.sh
echo.

pause
