@echo off
REM Build script for DPI Packet Analyzer (Java Version)

echo Building DPI Packet Analyzer...
echo.

set JAVA_SRC=src\main\java
set OUT_DIR=build\classes
set JAR_FILE=packet-analyzer.jar
set MANIFEST_FILE=MANIFEST.MF

REM Create output directories
if not exist %OUT_DIR% mkdir %OUT_DIR%
if not exist build mkdir build

REM Compile all Java files
echo Compiling Java files...
javac -d %OUT_DIR% -encoding UTF-8 ^
    %JAVA_SRC%\com\dpi\types\*.java ^
    %JAVA_SRC%\com\dpi\parser\*.java ^
    %JAVA_SRC%\com\dpi\tracking\*.java ^
    %JAVA_SRC%\com\dpi\engine\*.java ^
    %JAVA_SRC%\com\dpi\*.java

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b 1
)

echo Compilation successful!
echo.

REM Create manifest file
echo Creating manifest...
(
    echo Manifest-Version: 1.0
    echo Main-Class: com.dpi.PacketAnalyzerMain
    echo Implementation-Title: DPI Packet Analyzer
    echo Implementation-Version: 1.0.0
) > %MANIFEST_FILE%

REM Create JAR file
echo Creating JAR file...
jar cvfm %JAR_FILE% %MANIFEST_FILE% -C %OUT_DIR% .

if %ERRORLEVEL% NEQ 0 (
    echo JAR creation failed!
    exit /b 1
)

echo.
echo Build complete!
echo.
echo Usage:
echo   java -jar %JAR_FILE% input.pcap output.pcap [rules.txt]
echo.
