@echo off
REM Manual test script for DNS tunnel (Windows)
REM This script helps test the implementation

echo === DNS Tunnel Test Script ===
echo.
echo This script will help you test the DNS tunnel implementation.
echo Make sure you have Rust installed and cargo is in your PATH.
echo.

REM Check if cargo is available
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: cargo is not installed or not in PATH
    echo Please install Rust from https://rustup.rs/
    exit /b 1
)

echo Cargo found:
cargo --version
echo.

REM Build the project
echo Building project...
cargo build --release

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed!
    exit /b 1
)

echo Build successful!
echo.

REM Run unit tests
echo Running tests...
cargo test

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Some tests failed
) else (
    echo All tests passed!
)

echo.
echo === Test Complete ===
echo.
echo Binaries are available at:
echo   - target\release\client.exe
echo   - target\release\server.exe
echo.
echo To test manually:
echo 1. Start the server: target\release\server.exe --config server-config.json
echo 2. Start the client: target\release\client.exe --config client-config.json
echo 3. Send UDP packets to the client's local UDP address
