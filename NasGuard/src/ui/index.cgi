#!/bin/sh
for p in /usr/bin/python3 /bin/python3 /usr/local/bin/python3; do
  [ -x "$p" ] && exec "$p" "$(dirname "$0")/proxy.py"
done
printf 'Status: 500\r\nContent-Type: text/plain\r\n\r\npython3 not found\n'
