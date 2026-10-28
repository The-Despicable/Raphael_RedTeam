#!/bin/sh
cd /opt/gophish || exit 1
if [ ! -f /tmp/gophish.pid ] || ! kill -0 "$(cat /tmp/gophish.pid)" 2>/dev/null; then
  nohup /opt/gophish/gophish >/tmp/gophish.log 2>&1 &
  echo $! >/tmp/gophish.pid
fi
cd /app
exec uvicorn main:app --host 0.0.0.0 --port 3502
