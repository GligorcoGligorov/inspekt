#!/usr/bin/env bash
# Runs the MariaDB store tests against a throwaway container, so they never
# touch the compose stack's data. CI uses a service container instead.
set -euo pipefail
cd "$(dirname "$0")/.."

name=inspekt-testdb
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --rm --name "$name" -p 127.0.0.1:3307:3306 \
	-e MARIADB_RANDOM_ROOT_PASSWORD=1 -e MARIADB_DATABASE=inspekt_test \
	-e MARIADB_USER=inspekt -e MARIADB_PASSWORD=inspekt \
	mariadb:11.4 --innodb-buffer-pool-size=32M --performance-schema=OFF >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT

for _ in $(seq 60); do
	docker exec "$name" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1 && break
	sleep 1
done

INSPEKT_TEST_MARIADB_DSN='inspekt:inspekt@tcp(127.0.0.1:3307)/inspekt_test' \
	go test -count=1 -race -run 'TestMariaDB' -v ./internal/store
