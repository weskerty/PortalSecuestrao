#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock &


cd ~/portal || exit 1

# Para Actualizaciones, podes evitar y ejecutar directo node server.js
git fetch origin

L=$(git rev-parse HEAD)
R=$(git rev-parse origin/master)

[ "$L" = "$R" ] && exit 0

git reset --hard origin/master

if git diff --name-only "$L" "$R" | grep -qE '(^|/)(package\.json|package-lock\.json)$'; then
  npm install --force
fi

pkill -f "node server.js" 2>/dev/null
node server.js 

