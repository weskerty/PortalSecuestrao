# PortalSecuestrao
WiFi Portal Cautivo - Linux/Termux


Reutiliza el anclaje del telefono para limitar ususarios y solo permitir acceso a ciertas aplicaciones, de esta manera evitar que los clientes utilicen el ancho de banda ajeno.

Ejemplo quieres que tus amigos usen WiFi, pero tienes un plan de datos limitados, entonces esto solo permite que se conecten a WhatsApp y nada mas. Asi se evita los casos cuando se conectan y PlayStore empieza a descargar actualizaciones consumiendo todos tus megas 🫩

Claramente Requiere ROOT y el Anclaje ya debe estar activo desde antes, se puede automatizar con [Tasker ↗️](https://play.google.com/store/apps/details?id=net.dinglisch.android.taskerm) y otras AutoApps.

## Instalar
Abre Termux y Pegalo, se iniciara automaticamente al terminar. Recuerda tener tu Anclaje/Hotspot activado antes de ejecutar.
ˋˋˋ

ˋˋˋ

Para auto inicio debes editar tu .bashrc o utilizar [Tasker ↗️](https://play.google.com/store/apps/details?id=net.dinglisch.android.taskerm), [Termux Boot ↗️](https://wiki.termux.com/wiki/Termux:Boot) o como gustes autoiniciar.

### Limitaciones
En Android 12 y Superior el sistema mata termux, si te sucede deberas seguir [Esta Guia ↗️](https://github.com/weskerty/TermuxGod#nokill---no-kill-termux-by-system)

En Android 12 y Superior Tasker no puede autoIniciar el Anclaje/Hotspot y requiere su app Hermana tambien instalada: [TaskerSettings ↗️](https://github.com/joaomgcd/TaskerSettings/releases) 

Dependiendo del telefono algunos permiten mas clientes conectados algunos menos, Algunas Rom Permiten hasta 32 personas como maximo, desconozco otros limites. Algunas Roms tambien permiten compartir tu VPN si esta activado en los ajustes del Anclaje/Hotspot

Si encuentras errores o mejoras inicia un PullR 🫂
