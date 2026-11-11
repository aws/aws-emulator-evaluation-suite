"""locking-read-conflicts-rejected-at-commit."""
from __future__ import annotations

import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "locking-read-conflicts-rejected-at-commit"
GROUP = "transactions"
SERVICES = ["dsql"]

_OC000 = ("40001", "change conflicts with another transaction (OC000)")


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """Optimistic concurrency judges reads by locking clause: a plain read of a row another session
    then changes still commits, SELECT ... FOR UPDATE fails its commit with OC000, and FOR KEY SHARE
    conflicts with a concurrent DELETE but not with a non-key UPDATE."""
    dsql = ctx.client("dsql")
    identifier = _create_cluster(ctx, dsql)
    host = _wait_active(dsql, identifier)["endpoint"]
    table = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    token = dsql.generate_db_connect_admin_auth_token(Hostname=host, Region=ctx.region, ExpiresIn=900)
    a = _connect_ready(ctx, host, token)
    b = _connect(ctx, host, token)
    try:
        with a.cursor() as cur:
            cur.execute(f"CREATE TABLE {table} (id INT PRIMARY KEY, n INT)")
        a.commit()
        with a.cursor() as cur:
            cur.execute(f"INSERT INTO {table} VALUES (1, 0), (2, 0), (3, 0)")
        a.commit()

        def n(conn, row_id):
            with conn.cursor() as cur:
                cur.execute(f"SELECT n FROM {table} WHERE id = %s", (row_id,))
                found = cur.fetchone()
            return None if found is None else found[0]

        def b_commits(statement):
            with b.cursor() as cur:
                cur.execute(statement)
            b.commit()

        # A plain read does not conflict, and the reader keeps its snapshot.
        assert n(a, 1) == 0, "the seeded row did not read back"
        b_commits(f"UPDATE {table} SET n = 1 WHERE id = 1")
        assert n(a, 1) == 0, "a REPEATABLE READ transaction saw a write committed after its snapshot"
        with a.cursor() as cur:
            cur.execute(f"UPDATE {table} SET n = 10 WHERE id = 2")
        a.commit()
        assert (n(a, 1), n(a, 2)) == (1, 10), "the plain-read transaction did not commit its write"
        a.rollback()

        # FOR UPDATE adjudicates the read row as written.
        with a.cursor() as cur:
            cur.execute(f"SELECT n FROM {table} WHERE id = 1 FOR UPDATE")
            cur.execute(f"UPDATE {table} SET n = 20 WHERE id = 2")
        b_commits(f"UPDATE {table} SET n = 2 WHERE id = 1")
        got = _commit_error(a)
        assert got == _OC000, f"a FOR UPDATE read of a row changed underneath it committed as {got!r}"
        assert (n(a, 1), n(a, 2)) == (2, 10), "the losing FOR UPDATE transaction left a write behind"
        a.rollback()

        # FOR KEY SHARE does not conflict with an UPDATE of a non-key column.
        with a.cursor() as cur:
            cur.execute(f"SELECT n FROM {table} WHERE id = 1 FOR KEY SHARE")
            cur.execute(f"UPDATE {table} SET n = 30 WHERE id = 2")
        b_commits(f"UPDATE {table} SET n = 3 WHERE id = 1")
        a.commit()
        assert (n(a, 1), n(a, 2)) == (3, 30), "FOR KEY SHARE against a non-key UPDATE did not commit both"
        a.rollback()

        # FOR KEY SHARE conflicts with a DELETE of the row.
        with a.cursor() as cur:
            cur.execute(f"SELECT n FROM {table} WHERE id = 3 FOR KEY SHARE")
            cur.execute(f"UPDATE {table} SET n = 40 WHERE id = 2")
        b_commits(f"DELETE FROM {table} WHERE id = 3")
        got = _commit_error(a)
        assert got == _OC000, f"a FOR KEY SHARE read of a row deleted underneath it committed as {got!r}"
        assert (n(a, 2), n(a, 3)) == (30, None), "the losing FOR KEY SHARE transaction left a write behind"
        a.rollback()
    finally:
        a.close()
        b.close()


def _commit_error(conn) -> tuple[str, str]:
    """(SQLSTATE, primary message) of a COMMIT that must fail; a successful commit raises."""
    try:
        conn.commit()
    except psycopg.Error as exc:
        conn.rollback()
        return exc.sqlstate, exc.diag.message_primary
    raise AssertionError("expected the commit to be refused, but it succeeded")


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
