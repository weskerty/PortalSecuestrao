#!/data/data/com.termux/files/usr/bin/bash
cd ~/portal
pkill -f "node server.js" 2>/dev/null
node server.js &
