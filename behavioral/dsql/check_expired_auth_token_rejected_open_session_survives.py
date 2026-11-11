"""expired-auth-token-rejected-open-session-survives."""
from __future__ import annotations

import re
import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expired-auth-token-rejected-open-session-survives"
GROUP = "authentication"
SERVICES = ["dsql"]

#: The token lifetime under test, long enough for the first connection to complete inside it, and
#: how long past its expiry the second connection waits. The token is a time contract (documented:
#: it authenticates the connection only, and an established connection outlives it), so this
#: asserts an ordering, never a speed.
_TOKEN_TTL_S = 20
_PAST_EXPIRY_S = 15


# timing:real-time — ttl: 20 s https://docs.aws.amazon.com/aurora-dsql/latest/userguide/SECTION_authentication-token.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An expired auth token opens no new connection, while the session it opened before expiry
    keeps serving SQL and a freshly generated token connects again."""
    dsql = ctx.client("dsql")
    identifier = _create_cluster(ctx, dsql)
    host = _wait_active(dsql, identifier)["endpoint"]
    _connect_ready(ctx, host, dsql.generate_db_connect_admin_auth_token(
        Hostname=host, Region=ctx.region, ExpiresIn=900)).close()

    issued = time.monotonic()
    short = dsql.generate_db_connect_admin_auth_token(Hostname=host, Region=ctx.region, ExpiresIn=_TOKEN_TTL_S)
    early = _connect(ctx, host, short)
    try:
        time.sleep(max(0.0, issued + _TOKEN_TTL_S + _PAST_EXPIRY_S - time.monotonic()))
        try:
            late = _connect(ctx, host, short)
        except psycopg.OperationalError as exc:
            text = str(exc)
            fatal = set(re.findall(r"FATAL:  ([^\n]*)", text))
            hints = {h.split(":", 1)[0] for h in re.findall(r"HINT:  ([^\n]*)", text)}
        else:
            late.close()
            raise AssertionError(f"a token {_PAST_EXPIRY_S}s past its {_TOKEN_TTL_S}s lifetime still opened a connection")
        assert fatal == {"unable to accept connection, access denied"}, (
            f"a connection with an expired token was refused with {fatal!r}"
        )
        assert hints == {"Signature expired"}, f"the expired-token refusal carried hints {hints!r}"

        with early.cursor() as cur:
            cur.execute("SELECT current_user")
            row = cur.fetchone()
        assert row == ("admin",), f"the session opened before expiry answered {row!r}, expected ('admin',)"
    finally:
        early.close()

    fresh = dsql.generate_db_connect_admin_auth_token(Hostname=host, Region=ctx.region, ExpiresIn=900)
    conn = _connect(ctx, host, fresh)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone() == (1,), "a freshly generated token did not open a working session"
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
