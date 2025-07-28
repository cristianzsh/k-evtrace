@echo off
setlocal

echo ==================================
echo Building k-evtrace.exe with Nuitka
echo ==================================

REM Path to main script
set MAIN=k-evtrace.py

REM Output folder
set OUTDIR=build

REM Icon file
set ICON=k_evtrace.ico

REM Metadata
set COMPANY="Cristian Souza"
set PRODUCT="k-evtrace"
set VERSION=0.0.1
set DESC="Sigma-based EVTX Analyzer"

REM Clean previous build
if exist %OUTDIR% rmdir /s /q %OUTDIR%

REM Compile with Nuitka
python -m nuitka ^
  --standalone ^
  --onefile ^
  --follow-imports ^
  --output-dir=%OUTDIR% ^
  --windows-icon-from-ico=%ICON% ^
  --windows-company-name=%COMPANY% ^
  --windows-product-name=%PRODUCT% ^
  --windows-file-version=%VERSION% ^
  --windows-product-version=%VERSION% ^
  --windows-file-description=%DESC% ^
  --include-package=Evtx ^
  --include-package=tqdm ^
  --include-package=tabulate ^
  --include-package=yaml ^
  --include-package=requests ^
  %MAIN%

endlocal
