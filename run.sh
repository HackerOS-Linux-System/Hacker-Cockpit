#!/bin/bash
run.sh - Script to launch HackerOS-Cockpit AppImage and open in Vivaldi browser
Path to the AppImage
APPIMAGE_PATH="/usr/share/HackerOS/Scripts/HackerOS-Apps/HackerOS-Cockpit.AppImage"
Make sure the AppImage is executable
chmod +x "$APPIMAGE_PATH"
Run the AppImage in the background
"$APPIMAGE_PATH" &
Wait a few seconds for the server to start (adjust if needed)
sleep 5
Open Vivaldi browser at the application URL
vivaldi "http://localhost:4545" &
