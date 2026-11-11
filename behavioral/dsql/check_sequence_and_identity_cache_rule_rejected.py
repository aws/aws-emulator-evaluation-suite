"""sequence-and-identity-cache-rule-rejected."""
from __future__ import annotations

import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sequence-and-identity-cache-rule-rejected"
GROUP = "sql-compatibility"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """Sequences and identity columns must declare CACHE 1 or CACHE >= 65536 (anything else, and
    SERIAL, is refused); a CACHE 1 sequence hands out 1, 2, 3 and a GENERATED ALWAYS identity
    refuses an explicit value without OVERRIDING SYSTEM VALUE."""
    dsql = ctx.client("dsql")
    identifier = _create_cluster(ctx, dsql)
    host = _wait_active(dsql, identifier)["endpoint"]
    seq = ctx.unique_name("sim2real_seq_").replace("-", "_")
    table = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    conn = _connect_ready(ctx, host, dsql.generate_db_connect_admin_auth_token(
        Hostname=host, Region=ctx.region, ExpiresIn=900))
    try:
        cache_rule = "please define CACHE greater than or equal to 65536 or equal to 1"
        got = _sql_error(conn, f"CREATE SEQUENCE {seq}_bare")
        assert got == ("0A000", f"CREATE SEQUENCE is not supported without an explicit cache size. {cache_rule}"), (
            f"CREATE SEQUENCE without CACHE answered {got!r}"
        )
        got = _sql_error(conn, f"CREATE SEQUENCE {seq}_two CACHE 2")
        assert got == ("22023", "CACHE (2) must be greater than or equal to 65536 or equal to 1"), (
            f"CREATE SEQUENCE ... CACHE 2 answered {got!r}"
        )
        got = _sql_error(conn, f"CREATE TABLE {table}_bare (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY)")
        assert got == ("0A000", f"identity column is not supported without an explicit cache size. {cache_rule}"), (
            f"an identity column without CACHE answered {got!r}"
        )
        got = _sql_error(conn, f"CREATE TABLE {table}_serial (id SERIAL PRIMARY KEY)")
        assert got == ("42704", 'type "serial" does not exist'), f"a SERIAL column answered {got!r}"

        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_class WHERE relname LIKE %s", (f"{seq}_%",))
            assert cur.fetchone() == (0,), "a refused CREATE SEQUENCE left a sequence behind"
        conn.rollback()

        with conn.cursor() as cur:
            cur.execute(f"CREATE SEQUENCE {seq} CACHE 1")
        conn.commit()
        values = []
        for _ in range(3):
            with conn.cursor() as cur:
                cur.execute(f"SELECT nextval('{seq}')")
                values.append(cur.fetchone()[0])
            conn.commit()
        assert values == [1, 2, 3], f"a CACHE 1 sequence handed out {values!r}, expected [1, 2, 3]"

        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table} (id BIGINT GENERATED ALWAYS AS IDENTITY (CACHE 1) PRIMARY KEY, v TEXT)")
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO {table} (v) VALUES ('a'), ('b') RETURNING id")
            generated = [r[0] for r in cur.fetchall()]
        conn.commit()
        assert generated == [1, 2], f"the identity column generated {generated!r}, expected [1, 2]"

        got = _sql_error(conn, f"INSERT INTO {table} (id, v) VALUES (100, 'explicit')")
        assert got == ("428C9", 'cannot insert a non-DEFAULT value into column "id"'), (
            f"an explicit value for a GENERATED ALWAYS identity answered {got!r}"
        )
        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO {table} (id, v) OVERRIDING SYSTEM VALUE VALUES (100, 'override') RETURNING id")
            assert cur.fetchone() == (100,), "OVERRIDING SYSTEM VALUE did not keep the explicit id"
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(f"SELECT id, v FROM {table} ORDER BY id")
            rows = cur.fetchall()
        conn.rollback()
        assert rows == [(1, "a"), (2, "b"), (100, "override")], f"the identity table reads back as {rows!r}"
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
