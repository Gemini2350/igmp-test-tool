@echo off
rem Windows: Doppelklick startet das IGMP Test Tool und oeffnet den Browser.
cd /d "%~dp0"
py igmp_join_tool.py 2>nul || python igmp_join_tool.py
pause
