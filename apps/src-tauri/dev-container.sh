#!/bin/sh
set -eu

display="${DISPLAY:-:99}"
resolution="${OPENOM_DESKTOP_RESOLUTION:-1440x900}"
export DISPLAY="$display"

Xvfb "$display" -screen 0 "${resolution}x24" -nolisten tcp -ac &

attempt=0
until xdpyinfo -display "$display" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "[desktop] Xvfb did not become ready" >&2
    exit 1
  fi
  sleep 1
done

openbox >/tmp/openbox.log 2>&1 &
x11vnc -display "$display" -forever -shared -nopw -localhost -noxdamage -quiet &
websockify --web=/usr/share/novnc 0.0.0.0:6080 localhost:5900 &

workspace_wait=0
while [ ! -f /work/apps/package.json ]; do
  workspace_wait=$((workspace_wait + 1))
  if [ "$workspace_wait" -eq 30 ]; then
    echo "[desktop] no workspace synced; start this container with 'task dev:desktop'" >&2
  fi
  sleep 1
done

cd /work/apps
pnpm config set store-dir /pnpm/store
pnpm install --frozen-lockfile

echo "[desktop] noVNC is ready at http://localhost:6080/vnc_auto.html?autoconnect=true&resize=scale"
exec dbus-run-session -- pnpm dev
