@echo off
echo Fixing npm install issues...

REM Backup current .npmrc
if exist .npmrc (
    echo Backing up .npmrc to .npmrc.backup
    copy .npmrc .npmrc.backup
)

REM Create minimal .npmrc for Windows compatibility
echo Creating Windows-compatible .npmrc
echo fund=false > .npmrc
echo audit=false >> .npmrc

REM Clean npm cache
echo Cleaning npm cache...
npm cache clean --force

REM Remove node_modules if exists
if exist node_modules (
    echo Removing existing node_modules...
    rmdir /s /q node_modules
)

REM Remove package-lock.json if exists
if exist package-lock.json (
    echo Removing package-lock.json...
    del package-lock.json
)

REM Install dependencies
echo Installing dependencies...
npm install

REM Check if install was successful
if exist node_modules (
    echo ✅ npm install successful!
    echo Testing basic server startup...
    node -e "console.log('✅ Node.js working'); console.log('Testing requires...'); try { require('express'); console.log('✅ Express loaded'); } catch(e) { console.error('❌ Express error:', e.message); }"
) else (
    echo ❌ npm install failed
    echo Restoring original .npmrc...
    if exist .npmrc.backup (
        copy .npmrc.backup .npmrc
        del .npmrc.backup
    )
)

pause
