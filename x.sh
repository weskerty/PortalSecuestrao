#!/data/data/com.termux/files/usr/bin/bash
# Arranca el portal, se actualiza si hay cambios y lo relanza si se cae.

termux-wake-lock 2>/dev/null &

# El directorio del propio script, no una ruta fija: la instalacion puede
# llamarse ~/portal, ~/wifi o cualquier otra cosa.
cd "$(dirname "$(readlink -f "$0")")" || exit 1

# Rama por defecto del remoto; si no hay remoto, la rama local.
BR=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)
BR=${BR#origin/}
[ -z "$BR" ] && BR=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
[ -z "$BR" ] && BR=main

# git reset --hard deja el arbol igual al commit destino: borra los archivos
# que ese commit no tenga y pisa las modificaciones locales de los que si.
# .env dejo de estar versionado, asi que la actualizacion que lo saca del
# indice lo borraria del disco; se guarda y se devuelve.
KEEP=".env public/index.html .snoop.json"

save_local() {
  rm -rf .keep_tmp
  mkdir -p .keep_tmp
  for f in $KEEP; do
    [ -e "$f" ] || continue
    mkdir -p ".keep_tmp/$(dirname "$f")"
    cp -a "$f" ".keep_tmp/$f"
  done
}

restore_local() {
  for f in $KEEP; do
    [ -e ".keep_tmp/$f" ] || continue
    if [ ! -e "$f" ]; then
      mkdir -p "$(dirname "$f")"
      cp -a ".keep_tmp/$f" "$f"
      echo "x.sh: $f restaurado"
    fi
  done
  rm -rf .keep_tmp
}

update() {
  L=$(git rev-parse HEAD 2>/dev/null)
  git fetch origin "$BR" --quiet 2>/dev/null || { echo "x.sh: sin red, sigo con el codigo local"; return; }
  R=$(git rev-parse "origin/$BR" 2>/dev/null)
  [ -z "$R" ] && return
  [ "$L" = "$R" ] && return

  echo "x.sh: actualizando ${L:0:7} -> ${R:0:7}"
  save_local
  if git reset --hard "origin/$BR"; then
    restore_local
    if git diff --name-only "$L" "$R" | grep -qE '(^|/)package(-lock)?\.json$'; then
      npm install --force
    fi
  else
    echo "x.sh: reset fallido, sigo con lo local"
    rm -rf .keep_tmp
  fi
}

update

pkill -f "node server.js" 2>/dev/null
sleep 1

# El portal retira sus reglas de iptables al salir, asi que una caida no deja
# el hotspot sin DNS; y POST /api/stop sirve para aplicar un .env nuevo porque
# este bucle lo vuelve a levantar.
while true; do
  node server.js
  code=$?
  echo "x.sh: server.js termino (codigo $code)"
  case "$code" in
    70|75) ;;
    *) echo "x.sh: salida limpia o error de configuracion, no relanzo"; break ;;
  esac
  sleep 3
  update
done
