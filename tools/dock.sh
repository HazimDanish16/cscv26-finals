#!/usr/bin/env bash
# Usage (WSL): tools/dock.sh <chall-dir>   -- builds & runs the challenge's compose/Dockerfile locally, prints ports
cd "$1" || exit 1
if ls docker-compose.y*ml compose.y*ml >/dev/null 2>&1; then
  docker compose up -d --build && docker compose ps
else
  n=chall_$(basename "$PWD" | tr -c 'a-z0-9\n' _ | tr A-Z a-z)
  docker build -t "$n" . && docker run -d --rm --name "$n" -P "$n" && docker port "$n"
fi
echo "tear down: docker compose down  /  docker rm -f <name>"
