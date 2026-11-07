#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock &


cd ~/portal || exit 1

# Rama por defecto del remoto. Antes estaba fijo a "master", que no existe en
# este repo (origin/HEAD -> origin/main): git rev-parse fallaba, R quedaba
# vacio y el auto-update nunca llegaba a hacer nada, en silencio.
BR=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)
BR=${BR#origin/}
[ -z "$BR" ] && BR=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
[ -z "$BR" ] && BR=main

L=$(git rev-parse HEAD 2>/dev/null)
R=""

# Para Actualizaciones, podes evitar y ejecutar directo node server.js
if git fetch origin "$BR" --quiet 2>/dev/null; then
  R=$(git rev-parse "origin/$BR" 2>/dev/null)
else
  echo "x.sh: sin red o fetch fallido, se arranca con el codigo local"
fi

# Salir sin tocar nada SOLO si ya esta al dia Y hay un proceso vivo. El
# "[ "$L" = "$R" ] && exit 0" anterior salia tambien cuando el portal no
# estaba corriendo, asi que en un arranque limpio con el repo al dia no se
# iniciaba nunca.
if [ -n "$R" ] && [ "$L" = "$R" ] && pgrep -f "node server.js" >/dev/null 2>&1; then
  echo "x.sh: ya actualizado y corriendo"
  exit 0
fi

if [ -n "$R" ] && [ "$L" != "$R" ]; then
  echo "x.sh: actualizando ${L:0:7} -> ${R:0:7}"
  git reset --hard "origin/$BR" || echo "x.sh: reset fallido, sigo con lo local"
  if git diff --name-only "$L" "$R" | grep -qE '(^|/)package(-lock)?\.json$'; then
    npm install --force
  fi
fi

pkill -f "node server.js" 2>/dev/null
exec node server.js
