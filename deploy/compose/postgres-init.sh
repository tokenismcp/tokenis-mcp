#!/bin/sh
# Runs once, when the postgres volume is first created.
#   tokenis     -- owns the "tokenis" database: the gateway's shared state
#   crm_reader  -- may only SELECT the sample CRM table the gateway ingests
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
  -v tokenis_pw="$TOKENIS_DB_PASSWORD" -v reader_pw="$CRM_READER_PASSWORD" <<'SQL'
CREATE ROLE tokenis LOGIN PASSWORD :'tokenis_pw';
CREATE DATABASE tokenis OWNER tokenis;
CREATE ROLE crm_reader LOGIN PASSWORD :'reader_pw';
CREATE DATABASE crm;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname crm <<'SQL'
CREATE TABLE customers (
    id            TEXT PRIMARY KEY,
    customer_name TEXT NOT NULL,
    industry      TEXT NOT NULL,
    region        TEXT NOT NULL,
    size_band     TEXT NOT NULL,
    revenue_2024  NUMERIC(14, 1) NOT NULL,
    revenue_2025  NUMERIC(14, 1) NOT NULL,
    employees     INTEGER NOT NULL,
    embedding     TEXT
);
\copy customers FROM '/seed/customers.csv' WITH (FORMAT csv, HEADER true)
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE crm TO crm_reader;
GRANT USAGE ON SCHEMA public TO crm_reader;
GRANT SELECT ON customers TO crm_reader;
SQL
