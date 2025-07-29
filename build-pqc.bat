@echo off
REM Build script for Signal-Server with Post-Quantum Cryptography support
REM This script builds the project using the PQC-enabled pom.xml files

echo.
echo =====================================
echo Building Signal-Server with PQC Support
echo =====================================
echo.

REM Check if Maven is available
where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Maven is not installed or not in PATH
    echo Please install Maven and try again
    exit /b 1
)

REM Backup original pom.xml files
echo Backing up original pom.xml files...
if exist pom.xml (
    copy pom.xml pom.xml.original >nul 2>&1
    echo - Root pom.xml backed up
)

if exist service\pom.xml (
    copy service\pom.xml service\pom.xml.original >nul 2>&1
    echo - Service pom.xml backed up
)

REM Replace with PQC-enabled pom.xml files
echo.
echo Replacing with PQC-enabled pom.xml files...
if exist pom-pqc.xml (
    copy pom-pqc.xml pom.xml >nul 2>&1
    echo - Root pom.xml replaced with PQC version
) else (
    echo WARNING: pom-pqc.xml not found, using original pom.xml
)

if exist service\pom-pqc.xml (
    copy service\pom-pqc.xml service\pom.xml >nul 2>&1
    echo - Service pom.xml replaced with PQC version
) else (
    echo WARNING: service\pom-pqc.xml not found, using original service\pom.xml
)

REM Clean previous builds
echo.
echo Cleaning previous builds...
call mvn clean -q
if %errorlevel% neq 0 (
    echo ERROR: Maven clean failed
    goto :restore_and_exit
)

REM Compile the project
echo.
echo Compiling project with PQC dependencies...
call mvn compile -q
if %errorlevel% neq 0 (
    echo ERROR: Maven compile failed
    echo This might be due to missing PQC dependencies
    echo Please check your internet connection and repository access
    goto :restore_and_exit
)

REM Run tests (specifically the PQC tests)
echo.
echo Running PQC tests...
call mvn test -Dtest=PQCryptoUtilTest -q
if %errorlevel% neq 0 (
    echo ERROR: PQC tests failed
    echo Check the test output above for details
    goto :restore_and_exit
) else (
    echo SUCCESS: PQC tests passed!
)

REM Package the project
echo.
echo Packaging project...
call mvn package -DskipTests -q
if %errorlevel% neq 0 (
    echo ERROR: Maven package failed
    goto :restore_and_exit
)

echo.
echo =====================================
echo Build completed successfully!
echo =====================================
echo.
echo The Signal-Server has been built with post-quantum cryptography support.
echo The following algorithms are now available:
echo   - CRYSTALS-Kyber for key encapsulation (replaces ECDH)
echo   - CRYSTALS-Dilithium for digital signatures (replaces ECDSA)
echo.
echo Next steps:
echo 1. Review the PQCryptoUtil class in service\src\main\java\org\whispersystems\textsecuregcm\crypto\
echo 2. Integrate PQC algorithms into the Signal messaging protocols
echo 3. Update key storage and management systems
echo 4. Test with Signal clients that support post-quantum cryptography
echo.

goto :restore_pom

:restore_and_exit
echo.
echo Build failed, restoring original pom.xml files...

:restore_pom
REM Restore original pom.xml files
if exist pom.xml.original (
    copy pom.xml.original pom.xml >nul 2>&1
    del pom.xml.original >nul 2>&1
    echo - Root pom.xml restored
)

if exist service\pom.xml.original (
    copy service\pom.xml.original service\pom.xml >nul 2>&1
    del service\pom.xml.original >nul 2>&1
    echo - Service pom.xml restored
)

if "%1"=="restore_and_exit" (
    exit /b 1
)

echo.
echo Build process completed.
pause
