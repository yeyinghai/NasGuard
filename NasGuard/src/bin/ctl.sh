#!/bin/sh
# NasGuard 控制脚本（经 setuid 助手以 root 运行）
PKG=/var/packages/NasGuard
APP=$PKG/target/app/guard.py
VAR=$PKG/var
PID=$VAR/guard.pid
LOG=$VAR/nasguard.log
mkdir -p "$VAR"

py() {
  for p in /usr/bin/python3 /bin/python3 /usr/local/bin/python3; do [ -x "$p" ] && { echo "$p"; return; }; done
  command -v python3
}

running() { [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; }

case "$1" in
  start)
    running && exit 0
    PY=$(py); [ -n "$PY" ] || { echo "找不到 python3" >> "$LOG"; exit 1; }
    [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 1048576 ] && mv -f "$LOG" "$LOG.1"
    if command -v setsid >/dev/null 2>&1; then
      setsid "$PY" "$APP" daemon >> "$LOG" 2>&1 < /dev/null &
    else
      nohup "$PY" "$APP" daemon >> "$LOG" 2>&1 < /dev/null &
    fi
    echo $! > "$PID"
    sleep 1
    running
    ;;
  stop)
    if running; then
      kill "$(cat "$PID")" 2>/dev/null
      i=0; while running && [ $i -lt 10 ]; do sleep 1; i=$((i + 1)); done
      running && kill -9 "$(cat "$PID")" 2>/dev/null
    fi
    rm -f "$PID"
    PY=$(py); [ -n "$PY" ] && "$PY" "$APP" fwclean >> "$LOG" 2>&1
    exit 0
    ;;
  restart)
    "$0" stop; "$0" start
    ;;
  status)
    running
    ;;
esac
