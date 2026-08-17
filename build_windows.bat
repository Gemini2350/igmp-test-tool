@echo off
rem Builds "IGMP Test Tool.exe" on a Windows machine.
rem Requires: Python 3.x from python.org (with "Add to PATH").
cd /d "%~dp0"
py -m pip install pyinstaller || python -m pip install pyinstaller
py -m PyInstaller --noconfirm --onefile --windowed --name "IGMP Test Tool" igmp_join_gui.py || python -m PyInstaller --noconfirm --onefile --windowed --name "IGMP Test Tool" igmp_join_gui.py
echo.
echo Done: dist\"IGMP Test Tool.exe"
pause
