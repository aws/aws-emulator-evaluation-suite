"""connection-without-tls-or-admin-token-rejected."""
from __future__ import annotations

import re
import ssl
import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-without-tls-or-admin-token-rejected"
GROUP = "authentication"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """The SQL endpoint refuses a plaintext connection and any password that is not an admin auth
    token for this cluster, while an admin token over TLS opens a working session."""
    dsql = ctx.client("dsql")
    identifier = _create_cluster(ctx, dsql)
    host = _wait_active(dsql, identifier)["endpoint"]
    admin_token = dsql.generate_db_connect_admin_auth_token(Hostname=host, Region=ctx.region, ExpiresIn=900)

    conn = _connect_ready(ctx, host, admin_token)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user, 1 + 1")
            row = cur.fetchone()
    finally:
        conn.close()
    assert row == ("admin", 2), f"an admin session over TLS answered {row!r}, expected ('admin', 2)"

    fatal, _ = _refusal(lambda: _connect(ctx, host, admin_token, sslmode="disable"))
    assert fatal == {"unable to accept connection, SSL is mandatory. AWS Authentication is required."}, (
        f"a plaintext connection with a valid admin token was refused with {fatal!r}"
    )

    connect_token = dsql.generate_db_connect_auth_token(Hostname=host, Region=ctx.region, ExpiresIn=900)
    fatal, hints = _refusal(lambda: _connect(ctx, host, connect_token))
    assert fatal == {"unable to accept connection, access denied"}, (
        f"a DbConnect token presented for the admin role was refused with {fatal!r}"
    )
    assert hints == {"Wrong user to action mapping. user: admin, action: DbConnect"}, (
        f"the refusal of a DbConnect token for admin carried hints {hints!r}"
    )

    fatal, _ = _refusal(lambda: _connect(ctx, host, "sim2real-not-an-auth-token"))
    assert fatal == {"unable to accept connection, access denied"}, (
        f"a password that is not an auth token was refused with {fatal!r}"
    )

    foreign_host = host.replace(identifier, "a" * len(identifier), 1)
    assert foreign_host != host, f"the endpoint {host!r} does not name cluster {identifier!r}"
    foreign_token = dsql.generate_db_connect_admin_auth_token(
        Hostname=foreign_host, Region=ctx.region, ExpiresIn=900
    )
    fatal, _ = _refusal(lambda: _connect(ctx, host, foreign_token))
    assert fatal == {"unable to accept connection, access denied"}, (
        f"an admin token signed for another cluster's host was refused with {fatal!r}"
    )

    conn = _connect(ctx, host, admin_token)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone() == (1,), "the admin token stopped working after the refusals"
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


def _connect(ctx, host: str, token: str, *, user: str = "admin", sslmode: str | None = None):
    db_host, port = ctx.endpoint_host(host, 5432)
    return psycopg.connect(
        host=db_host, port=port, dbname="postgres", user=user, password=token,
        connect_timeout=20, **({"sslmode": sslmode} if sslmode else _tls(ctx)),
    )


# tls-subject: the check asserts DSQL refuses a session without TLS, so its TLS settings are explicit.
def _tls(ctx) -> dict:
    """libpq TLS settings that verify the endpoint's certificate as ctx.http_verify says."""
    if ctx.http_verify is False:
        return {"sslmode": "require"}
    if isinstance(ctx.http_verify, str):
        return {"sslmode": "verify-full", "sslrootcert": ctx.http_verify}
    return {"sslmode": "verify-full", "sslrootcert": ssl.get_default_verify_paths().cafile or "system"}


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


def _refusal(fn) -> tuple[set[str], set[str]]:
    """The server's FATAL and HINT lines over every address the driver tried; a success raises."""
    try:
        conn = fn()
    except psycopg.OperationalError as exc:
        text = str(exc)
        return set(re.findall(r"FATAL:  ([^\n]*)", text)), set(re.findall(r"HINT:  ([^\n]*)", text))
    conn.close()
    raise AssertionError("expected the connection to be refused, but it was accepted")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
