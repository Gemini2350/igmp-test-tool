@echo off
rem Windows: double-click starts the IGMP Test Tool and opens the browser.
cd /d "%~dp0"
py igmp_join_tool.py 2>nul || python igmp_join_tool.py
pause
