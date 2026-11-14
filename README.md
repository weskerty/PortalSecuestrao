# PortalSecuestrao
WiFi Portal Cautivo - Linux/Termux

# Español

Reutiliza el anclaje del telefono para limitar usuarios y solo permitir acceso a ciertas aplicaciones, de esta manera evitar que los clientes utilicen el ancho de banda ajeno.

Ejemplo quieres que tus amigos usen WiFi, pero tienes un plan de datos limitados, entonces esto solo permite que se conecten a WhatsApp y nada mas. Asi se evita los casos cuando se conectan y PlayStore empieza a descargar actualizaciones consumiendo todos tus megas 🫩

El portal no sabe nada de WhatsApp ni de ningun otro servicio: todo sale de una lista de dominios y rangos en el `.env`, asi que sirve igual para Telegram, el correo de la empresa o lo que pongas.

Claramente Requiere ROOT y el Anclaje ya debe estar activo desde antes, se puede automatizar con [Tasker ↗️](https://play.google.com/store/apps/details?id=net.dinglisch.android.taskerm) y otras AutoApps.

## Instalar

Abre Termux y Pegalo, se iniciara automaticamente al terminar. Recuerda tener tu Anclaje/Hotspot activado antes de ejecutar.

```
curl -fsSL https://raw.githubusercontent.com/weskerty/TermuxGod/main/Scripts/AutoScripts/PortalCautivo.sh | bash

```

Para auto inicio debes editar tu .bashrc o utilizar [Tasker ↗️](https://play.google.com/store/apps/details?id=net.dinglisch.android.taskerm), [Termux Boot ↗️](https://wiki.termux.com/wiki/Termux:Boot) o como gustes autoiniciar.

Funciona sin configurar nada: de fabrica deja pasar solo WhatsApp. La interfaz del hotspot y su IP se detectan solas.

## Configurar

Todo esta en `.env`, que se crea solo la primera vez copiando `.env.example`. Ese archivo documenta cada opcion; lo importante:

| | |
|---|---|
| `ALLOW_DOMAINS` | dominios permitidos. Se resuelven al arrancar y se aprenden del trafico DNS real, asi la lista de IPs se mantiene al dia sola. Match por sufijo. |
| `ALLOW_RANGES` | CIDRs permitidos tal cual, sin resolver nada. |
| `FREE_MACS` | MACs con acceso total, sin portal ni filtro. Son las unicas que pueden entrar al panel. |
| `SPEED` | limite por cliente en kbit/s. |
| `OPEN_MS` | ventana sin filtrar justo despues de autenticar. 0 es lo mas estricto y funciona. |
| `ADMIN` / `ADMIN_SHELL` | panel web y terminal remota. La terminal viene apagada. |

Al actualizar, tu `.env` no se toca: solo se le anaden las claves nuevas que falten. Lo mismo con `public/index.html`, que puedes editar para poner tu propia portada (la plantilla versionada es `public/index.default.html`).

Cambiar el `.env` requiere reiniciar el proceso para que surta efecto; desde el panel, el boton Stop lo reinicia porque `x.sh` lo vuelve a levantar.

### Panel

`http://<ip-del-hotspot>:8080/admin.html`, o desde el propio telefono en `http://127.0.0.1:8080/admin.html`. Muestra dispositivos conectados, que dominios consulta cada uno, el log, la configuracion y el estado de la red detectada. Pide usuario y clave (`ADMIN_USERS`) y ademas que la MAC este en `FREE_MACS`. Si no defines `ADMIN_USERS` se genera una clave aleatoria en cada arranque y se escribe en el log.

## Como funciona

1. El 53 de los clientes se redirige al DNS del propio portal. Los dominios permitidos se reenvian de verdad; el resto apunta al portal para que el movil saque el aviso de "iniciar sesion en la red".
2. El 80 se redirige al portal. Mientras el cliente no pulse CONECTAR, no sale ni un paquete.
3. Al autenticar, su MAC pasa a una cadena que solo acepta los destinos de la allowlist. Todo lo demas se rechaza al instante.
4. De las respuestas DNS de los dominios permitidos se aprenden las IPs nuevas y se anaden a la allowlist en caliente, con caducidad para que la lista no crezca sin fin.

El filtrado es solo IPv4, asi que el IPv6 del anclaje se corta entero (`BLOCK_IPV6=1`); si no, los clientes saldrian por v6 sin pasar por ninguna regla.

Con `ISOLATE=1` los clientes tampoco se ven entre ellos, ni alcanzan la red desde la que compartes, ni ningun puerto del telefono aparte del portal y el DNS.

Las reglas se retiran al cerrar el proceso. Si se van sin retirar (un `kill -9`), `x.sh` las limpia en el siguiente arranque.

### Limitaciones

En Android 12 y Superior el sistema mata termux, si te sucede deberas seguir [Esta Guia ↗️](https://github.com/weskerty/TermuxGod#nokill---no-kill-termux-by-system)

En Android 12 y Superior Tasker no puede autoIniciar el Anclaje/Hotspot y requiere su app Hermana tambien instalada: [TaskerSettings ↗️](https://github.com/joaomgcd/TaskerSettings/releases)

Dependiendo del telefono algunos permiten mas clientes conectados algunos menos, Algunas Rom Permiten hasta 32 personas como maximo, desconozco otros limites. Algunas Roms tambien permiten compartir tu VPN si esta activado en los ajustes del Anclaje/Hotspot

Las notificaciones push no viajan por los dominios de la app (APNs usa `17.0.0.0/8` puerto 5223, FCM usa `mtalk.google.com` puertos 5228-5230), asi que permitirlas implica abrir el rango entero de Apple o Google.

Si un invitado tiene el DNS privado de Android en modo estricto, su DNS no pasa por el portal y se queda sin resolver; hay que apagarlo en su movil.

El filtro es por MAC: cambiarla lo evita. Para compartir con amigos sin gastar los datos sobra, pero no es un control de acceso.

## Desarrollo

```
npm test
```

No necesita root ni hotspot: prueba el parseo del `.env`, la deteccion de interfaces contra salidas reales de `ip`/`dumpsys`, el armado de las cadenas de iptables y el proxy DNS completo contra un resolver falso.

Si encuentras errores o mejoras inicia un PullR 🫂
