#!/usr/bin/env bash
# Launch the ctf-solver GUI: start the local backend once, open an app window.
# Bound to Alt+T in Hyprland.
set -euo pipefail
PORT="${CTF_GUI_PORT:-8777}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${CTF_PYTHON:-python3}"
URL="http://127.0.0.1:${PORT}"
LOG="${XDG_RUNTIME_DIR:-/tmp}/krypt-gui.log"
# Ensure agent CLIs (claude in ~/.local/bin, agy in /usr/bin) resolve for the server.
export PATH="${HOME}/.local/bin:/usr/local/bin:/usr/bin:${PATH}"

# Start backend if the port isn't already serving.
if ! curl -s -o /dev/null --max-time 1 "${URL}/api/health"; then
  cd "$HERE"
  CTF_GUI_PORT="$PORT" nohup "$PY" server.py >"$LOG" 2>&1 &
  for _ in $(seq 1 40); do
    curl -s -o /dev/null --max-time 1 "${URL}/api/health" && break
    sleep 0.15
  done
fi

# Open a clean, kiosk-fullscreen app window (no browser chrome, no exit toast).
# Close it with your Hyprland kill bind (ALT+ESCAPE) or Alt+F4.
if command -v google-chrome-stable >/dev/null; then
  exec google-chrome-stable --app="$URL" --class="krypt" --kiosk \
       --user-data-dir="${HOME}/.config/krypt-chrome" >/dev/null 2>&1
elif command -v chromium >/dev/null; then
  exec chromium --app="$URL" --class="krypt" --kiosk >/dev/null 2>&1
else
  exec xdg-open "$URL"
fi
