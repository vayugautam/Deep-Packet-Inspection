@echo off
echo ====================================================
echo      Pushing DPI Java Project to GitHub
echo ====================================================
echo.

:: Initialize Git repository
git init

:: Rename default branch to main
git checkout -b main 2>nul || git branch -M main

:: Add files
git add src/ pom.xml README.md example_rules.txt .gitignore 2>nul
git add src pom.xml README.md example_rules.txt

:: Commit files
git commit -m "Initial commit of Deep Packet Inspection Java engine"

echo.
echo ====================================================
echo Repository has been initialized and files committed.
echo.
echo Now we will create the repository on GitHub.
echo If you have the GitHub CLI (gh) installed, we can do it automatically.
echo Otherwise, please create a new repository named "Deep Packet Inspection"
echo on github.com first.
echo ====================================================
echo.

where gh >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [Info] GitHub CLI (gh) detected.
    echo Creating repository "Deep Packet Inspection" on GitHub...
    gh repo create "Deep Packet Inspection" --public --source=. --remote=origin --push
) else (
    echo [Info] GitHub CLI not found.
    echo Please run the following commands manually to link and push:
    echo.
    echo 1. Create a public repository named "Deep Packet Inspection" on GitHub.
    echo 2. Run: git remote add origin https://github.com/YOUR_USERNAME/Deep-Packet-Inspection.git
    echo 3. Run: git push -u origin main
)

pause
