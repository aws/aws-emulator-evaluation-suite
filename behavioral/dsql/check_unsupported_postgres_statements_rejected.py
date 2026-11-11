"""unsupported-postgres-statements-rejected."""
from __future__ import annotations

import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsupported-postgres-statements-rejected"
GROUP = "sql-compatibility"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """PostgreSQL features Aurora DSQL documents as unsupported are refused with SQLSTATE 0A000 and
    leave the table untouched, while REPEATABLE READ, SELECT ... FOR UPDATE and DELETE FROM in place
    of TRUNCATE succeed."""
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
            cur.execute(f"INSERT INTO {table} VALUES (1, 10), (2, 20)")
        conn.commit()

        refused = {
            f"TRUNCATE {table}": "unsupported statement: Truncate",
            "CREATE TEMP TABLE sim2real_scratch (x INT)": "TEMPORARY or TEMP table not supported for CREATE TABLE",
            "CREATE EXTENSION pgcrypto": "unsupported statement: CreateExtension",
            "CREATE FUNCTION sim2real_one() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN 1; END $$":
                "CREATE FUNCTION with language plpgsql not supported",
            f"CREATE TRIGGER sim2real_trg BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION sim2real_none()":
                "CREATE TRIGGER not supported",
            f"CREATE INDEX sim2real_sync_idx ON {table} (n)": "unsupported mode. please use CREATE INDEX ASYNC.",
            f"VACUUM {table}": "unsupported VACUUM statement",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE": "Unsupported isolation level: SERIALIZABLE",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED": "Unsupported isolation level: READ COMMITTED",
            f"SELECT n FROM {table} FOR SHARE": "locking clauses other than FOR UPDATE/FOR KEY SHARE are not supported",
            f"LOCK TABLE {table}": "unsupported statement: Lock",
            "SELECT pg_advisory_lock(1)": "function pg_advisory_lock not supported",
            f"CREATE TABLE sim2real_part_{table} (id INT, k INT) PARTITION BY RANGE (k)":
                "PARTITION BY clause not supported for CREATE TABLE",
        }
        observed = {stmt: _sql_error(conn, stmt) for stmt in refused}
        wrong = {s: got for s, got in observed.items() if got != ("0A000", refused[s])}
        assert not wrong, f"statements refused differently than documented (SQLSTATE, message): {wrong!r}"

        with conn.cursor() as cur:
            cur.execute(f"SELECT id, n FROM {table} ORDER BY id")
            rows = cur.fetchall()
            cur.execute("SELECT count(*) FROM pg_class WHERE relname LIKE 'sim2real_s%' OR relname LIKE 'sim2real_part_%'")
            stray = cur.fetchone()[0]
        conn.rollback()
        assert rows == [(1, 10), (2, 20)], f"a refused statement changed the table: {rows!r}"
        assert stray == 0, f"refused DDL left {stray} relation(s) behind"

        with conn.cursor() as cur:
            cur.execute("SHOW transaction_isolation")
            assert cur.fetchone() == ("repeatable read",), "the session isolation level is not REPEATABLE READ"
            cur.execute(f"SELECT n FROM {table} WHERE id = 1 FOR UPDATE")
            assert cur.fetchone() == (10,), "SELECT ... FOR UPDATE did not return the row"
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(f"DELETE FROM {table}")
            assert cur.rowcount == 2, f"DELETE FROM, the documented TRUNCATE alternative, removed {cur.rowcount} rows"
        conn.commit()
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
