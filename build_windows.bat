@echo off
rem Baut "IGMP Test Tool.exe" auf einem Windows-Rechner.
rem Voraussetzung: Python 3.x von python.org (mit "Add to PATH").
cd /d "%~dp0"
py -m pip install pyinstaller || python -m pip install pyinstaller
py -m PyInstaller --noconfirm --onefile --windowed --name "IGMP Test Tool" igmp_join_gui.py || python -m PyInstaller --noconfirm --onefile --windowed --name "IGMP Test Tool" igmp_join_gui.py
echo.
echo Fertig: dist\"IGMP Test Tool.exe"
pause
