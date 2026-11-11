"""transaction-constraints-rejected."""
from __future__ import annotations

import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transaction-constraints-rejected"
GROUP = "transactions"
SERVICES = ["dsql"]

#: The documented per-transaction mutation limit (Aurora DSQL quotas: 3,000 rows, not configurable).
_ROW_LIMIT = 3000


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """A transaction may not mix DDL with DML, may hold only one DDL statement, and may mutate at
    most 3,000 rows; each violation is refused and the transaction commits nothing, while a single
    DDL and a 3,000-row INSERT each commit."""
    dsql = ctx.client("dsql")
    identifier = _create_cluster(ctx, dsql)
    host = _wait_active(dsql, identifier)["endpoint"]
    table = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    conn = _connect_ready(ctx, host, dsql.generate_db_connect_admin_auth_token(
        Hostname=host, Region=ctx.region, ExpiresIn=900))
    try:
        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table} (id INT PRIMARY KEY, n INT)")
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO {table} VALUES (1, 1)")
        got = _sql_error(conn, f"CREATE TABLE {table}_after_dml (x INT PRIMARY KEY)")
        assert got == ("0A000", "ddl and dml are not supported in the same transaction"), (
            f"DDL after DML in one transaction answered {got!r}"
        )

        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table}_before_dml (x INT PRIMARY KEY)")
        got = _sql_error(conn, f"INSERT INTO {table} VALUES (2, 2)")
        assert got == ("0A000", "ddl and dml are not supported in the same transaction"), (
            f"DML after DDL in one transaction answered {got!r}"
        )

        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table}_first (x INT PRIMARY KEY)")
        got = _sql_error(conn, f"CREATE TABLE {table}_second (x INT PRIMARY KEY)")
        assert got == ("0A000", "multiple ddl statements not supported in a transaction"), (
            f"a second DDL statement in one transaction answered {got!r}"
        )

        got = _sql_error(conn, f"INSERT INTO {table} SELECT g, g FROM generate_series(100, {100 + _ROW_LIMIT}) g")
        assert got == ("54000", "transaction row limit exceeded"), (
            f"inserting {_ROW_LIMIT + 1} rows in one transaction answered {got!r}"
        )

        with conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {table}")
            rows = cur.fetchone()[0]
            cur.execute(f"SELECT count(*) FROM pg_tables WHERE tablename LIKE '{table}_%'")
            tables = cur.fetchone()[0]
        conn.rollback()
        assert rows == 0, f"refused transactions left {rows} row(s) committed"
        assert tables == 0, f"refused transactions left {tables} table(s) created"

        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table}_alone (x INT PRIMARY KEY)")
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO {table} SELECT g, g FROM generate_series(1, {_ROW_LIMIT}) g")
            assert cur.rowcount == _ROW_LIMIT, f"a {_ROW_LIMIT}-row INSERT reported {cur.rowcount} rows"
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(f"SELECT count(*), min(id), max(id) FROM {table}")
            committed = cur.fetchone()
            cur.execute(f"SELECT count(*) FROM pg_tables WHERE tablename = '{table}_alone'")
            alone = cur.fetchone()[0]
        conn.rollback()
        assert committed == (_ROW_LIMIT, 1, _ROW_LIMIT), f"the {_ROW_LIMIT}-row commit reads back as {committed!r}"
        assert alone == 1, "a transaction holding a single DDL statement did not create its table"
    finally:
        conn.close()


# ===== helpers =====

_ACTIVE_TIMEOUT_S = 600.0
_CONNECT_TIMEOUT_S = 180.0


def _create_cluster(ctx, dsql) -> str:
    """An unprotected cluster, deleted by this check's teardown."""
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real": CHECK, "Name": ctx.unique_name("sim2real-behav-dsql-")},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(dsql, identifier))
    return identifier


def _delete_cluster(dsql, identifier: str) -> None:
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(dsql, identifier: str) -> dict:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        cluster = dsql.get_cluster(identifier=identifier)
        if cluster["status"] in ("ACTIVE", "FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(5)
    assert cluster["status"] == "ACTIVE", f"cluster settled in {cluster['status']!r}, not ACTIVE"
    assert cluster.get("endpoint"), f"an ACTIVE cluster published no endpoint: {cluster!r}"
    return cluster


def _connect(ctx, host: str, token: str, *, user: str = "admin"):
    db_host, port = ctx.endpoint_host(host, 5432)
    return psycopg.connect(
        host=db_host, port=port, dbname="postgres", user=user, password=token,
        connect_timeout=20, **_tls(),
    )


def _tls() -> dict:
    """libpq TLS settings: the session is encrypted without verifying the server's identity."""
    return {"sslmode": "require"}


def _connect_ready(ctx, host: str, token: str, *, user: str = "admin"):
    """A first connection right after ACTIVE can be refused while the endpoint warms up."""
    deadline = time.monotonic() + _CONNECT_TIMEOUT_S
    while True:
        try:
            return _connect(ctx, host, token, user=user)
        except psycopg.OperationalError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"no SQL connection within {_CONNECT_TIMEOUT_S}s: {exc}") from exc
            time.sleep(5)


def _sql_error(conn, statement: str) -> tuple[str, str]:
    """(SQLSTATE, primary message) of a statement that must fail; a success raises."""
    try:
        with conn.cursor() as cur:
            cur.execute(statement)
    except psycopg.Error as exc:
        conn.rollback()
        return exc.sqlstate, exc.diag.message_primary
    conn.rollback()
    raise AssertionError(f"expected {statement!r} to be refused, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
