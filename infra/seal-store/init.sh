#!/bin/sh
# Runs once, on the seal store container's first start (empty volume).
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /custos-seal-store/roles.dev.sql
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /custos-seal-store/schema.sql
