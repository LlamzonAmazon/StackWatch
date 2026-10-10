#!/usr/bin/env python3
"""Apply ClickHouse schema using admin credentials."""

import os
import re
import sys
from pathlib import Path

import clickhouse_connect

def create_app_user(client, admin_user: str) -> None:
    """Create the runtime user with INSERT and SELECT only, credentials from the environment."""
    app_user = os.environ.get("CLICKHOUSE_USER", "")
    app_pass = os.environ.get("CLICKHOUSE_PASSWORD", "")
    if not app_user or app_user == admin_user:
        print("CLICKHOUSE_USER unset or same as admin; skipping runtime user creation")
        return
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", app_user):
        sys.exit("CLICKHOUSE_USER must be a plain identifier")
    if not app_pass:
        sys.exit("CLICKHOUSE_PASSWORD must be set to create the runtime user")
    # DDL cannot use server-side parameters; the client escapes the bound password literal.
    client.command(f"CREATE USER IF NOT EXISTS {app_user} IDENTIFIED BY %(pw)s",
                   parameters={"pw": app_pass})
    client.command(f"GRANT INSERT, SELECT ON stackwatch.* TO {app_user}")
    print(f"Runtime user {app_user} ready")

def main():
    host = os.environ.get("CLICKHOUSE_HOST", "localhost")
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    admin_user = os.environ.get("CLICKHOUSE_ADMIN_USER", "default")
    admin_pass = os.environ.get("CLICKHOUSE_ADMIN_PASSWORD", "")

    schema_path = Path(__file__).parent / "schema.sql"

    print(f"Connecting to ClickHouse at {host}:{port} as {admin_user}...")

    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        username=admin_user,
        password=admin_pass,
    )

    sql = schema_path.read_text()

    # Split by semicolon and execute each statement
    statements = [s.strip() for s in sql.split(";") if s.strip()]

    for stmt in statements:
        if stmt:
            print(f"Executing: {stmt[:60]}...")
            client.command(stmt)

    print("Schema applied successfully!")

    create_app_user(client, admin_user)

    # Verify tables
    result = client.query("SHOW TABLES FROM stackwatch")
    print(f"Tables created: {[row[0] for row in result.result_rows]}")

if __name__ == "__main__":
    main()
