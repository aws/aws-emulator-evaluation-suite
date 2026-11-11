"""native-sql-round-trip-create-insert-select."""
from __future__ import annotations

import time

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing
from botocore.exceptions import ClientError

CHECK = "native-sql-round-trip-create-insert-select"
GROUP = "native-protocol"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """Aurora DSQL speaks the PostgreSQL wire protocol: after a cluster goes ACTIVE, an IAM auth token
    obtained from the DSQL client lets a real Postgres driver connect and round-trip CREATE TABLE / INSERT
    / SELECT. A backend that accepts CreateCluster but can't actually serve SQL must fail this check."""
    driver, driver_name = _load_pg_driver()
    if driver is None:
        raise RequiredToolMissing(['psycopg'])

    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "native-sql-round-trip-create-insert-select"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    active = _poll_until(
        lambda: dsql.get_cluster(identifier=identifier),
        lambda r: r["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert active["status"] == "ACTIVE", f"cluster never became ACTIVE: {active['status']}"
    endpoint = active["endpoint"]
    assert endpoint, "ACTIVE cluster did not expose a connection endpoint"

    token = dsql.generate_db_connect_admin_auth_token(
        Hostname=endpoint, Region=ctx.region, ExpiresIn=900
    )

    conn = _connect_with_retry(ctx, driver, endpoint, token, timeout_s=120.0, interval_s=5.0)
    try:
        table = ctx.unique_name("sim2real_dsql_tbl_").replace("-", "_")
        with conn.cursor() as cur:
            cur.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, val TEXT)")
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO {table} (id, val) VALUES (%s, %s)", (1, "hello-dsql"))
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(f"SELECT val FROM {table} WHERE id = %s", (1,))
            row = cur.fetchone()
        assert row is not None and row[0] == "hello-dsql", row

        with conn.cursor() as cur:
            cur.execute(f"DROP TABLE {table}")
        conn.commit()

        try:
            with conn.cursor() as cur:
                cur.execute(f"SELECT val FROM {table} WHERE id = %s", (1,))
        except driver.Error as exc:
            conn.rollback()
            assert "does not exist" in str(exc).lower(), (
                f"expected an undefined-table refusal after DROP TABLE, got: {exc}"
            )
        else:
            raise AssertionError(f"SELECT against dropped table {table} did not fail")
    finally:
        conn.close()


def _load_pg_driver():
    try:
        import psycopg  # type: ignore

        return psycopg, "psycopg"
    except ImportError:
        return None, None


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _connect_with_retry(ctx, driver, endpoint, token, *, timeout_s=120.0, interval_s=5.0):
    db_host, port = ctx.endpoint_host(endpoint, 5432)
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return driver.connect(
                host=db_host,
                port=port,
                dbname="postgres",
                user="admin",
                password=token,
                **_tls(),
                cursor_factory=driver.ClientCursor,
            )
        except Exception as exc:  # noqa: BLE001 - the DB may not accept connections the instant it's ACTIVE
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not open a SQL connection within {timeout_s}s: {last_exc}")


def _tls() -> dict:
    """libpq TLS settings: the session is encrypted without verifying the server's identity."""
    return {"sslmode": "require"}


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
