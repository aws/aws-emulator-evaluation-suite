"""iam-mapped-database-role-privileges-denied."""
from __future__ import annotations

import json
import re
import time

import psycopg
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-mapped-database-role-privileges-denied"
GROUP = "authorization"
SERVICES = ["dsql", "iam", "sts"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """A custom database role is reachable only through the IAM identity AWS IAM GRANT maps to it,
    holds no privilege it was not granted (SELECT only after GRANT, never INSERT or CREATE ROLE),
    and loses login when the mapping is revoked."""
    dsql = ctx.client("dsql")
    identifier = _create_cluster(ctx, dsql)
    cluster = _wait_active(dsql, identifier)
    host = cluster["endpoint"]
    db_role = ctx.unique_name("sim2real_role_").replace("-", "_")
    table = ctx.unique_name("sim2real_tbl_").replace("-", "_")

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-dsql-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="dbconnect", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dsql:DbConnect", "Resource": cluster["arn"]}]}))

    admin = _connect_ready(ctx, host, dsql.generate_db_connect_admin_auth_token(
        Hostname=host, Region=ctx.region, ExpiresIn=900))
    try:
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute(f"CREATE TABLE {table} (id INT PRIMARY KEY, v TEXT)")
            cur.execute(f"INSERT INTO {table} VALUES (1, 'seed')")
            cur.execute(f"CREATE ROLE {db_role} WITH LOGIN")
            cur.execute(f"AWS IAM GRANT {db_role} TO '{role_arn}'")
            cur.execute("SELECT pg_role_name FROM sys.iam_pg_role_mappings WHERE arn = %s", (role_arn,))
            mapped = [r[0] for r in cur.fetchall()]
        assert mapped == [db_role], f"sys.iam_pg_role_mappings maps the IAM role to {mapped!r}"

        role_dsql = ctx.client("dsql", creds=_assume(ctx, role_arn))
        role_token = role_dsql.generate_db_connect_auth_token(Hostname=host, Region=ctx.region, ExpiresIn=900)
        role_admin_token = role_dsql.generate_db_connect_admin_auth_token(
            Hostname=host, Region=ctx.region, ExpiresIn=900)

        session = _connect_ready(ctx, host, role_token, user=db_role)
        try:
            with session.cursor() as cur:
                cur.execute("SELECT current_user")
                assert cur.fetchone() == (db_role,), "the mapped session is not running as its role"
            session.rollback()

            fatal = _refused_login(lambda: _connect(ctx, host, role_admin_token))
            assert fatal == {"unable to accept connection, access denied"}, (
                f"an identity without dsql:DbConnectAdmin logging in as admin was refused with {fatal!r}"
            )
            denied = _sql_error(session, f"SELECT v FROM public.{table}")
            assert denied == ("42501", f"permission denied for table {table}"), (
                f"SELECT without a grant answered {denied!r}"
            )
        finally:
            session.close()

        with admin.cursor() as cur:
            cur.execute(f"GRANT SELECT ON public.{table} TO {db_role}")

        session = _connect(ctx, host, role_token, user=db_role)
        try:
            with session.cursor() as cur:
                cur.execute(f"SELECT v FROM public.{table} WHERE id = 1")
                assert cur.fetchone() == ("seed",), "SELECT after GRANT SELECT did not return the row"
            session.rollback()
            denied = _sql_error(session, f"INSERT INTO public.{table} VALUES (2, 'role')")
            assert denied == ("42501", f"permission denied for table {table}"), (
                f"INSERT with only SELECT granted answered {denied!r}"
            )
            denied = _sql_error(session, "CREATE ROLE sim2real_never_created WITH LOGIN")
            assert denied == ("42501", "permission denied to create role"), (
                f"CREATE ROLE from a non-admin role answered {denied!r}"
            )
        finally:
            session.close()

        with admin.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {table}")
            assert cur.fetchone() == (1,), "a refused INSERT changed the table"
            cur.execute(f"AWS IAM REVOKE {db_role} FROM '{role_arn}'")
            cur.execute("SELECT pg_role_name FROM sys.iam_pg_role_mappings WHERE arn = %s", (role_arn,))
            mapped = [r[0] for r in cur.fetchall()]
        assert mapped == [], f"sys.iam_pg_role_mappings still maps the IAM role to {mapped!r} after AWS IAM REVOKE"
        fatal = _refused_login_within(lambda: _connect(ctx, host, role_token, user=db_role), _REVOKE_TIMEOUT_S)
        assert fatal == {"unable to accept connection, access denied"}, (
            f"login after AWS IAM REVOKE was refused with {fatal!r}"
        )
    finally:
        admin.close()

    fresh = _connect(ctx, host, dsql.generate_db_connect_admin_auth_token(
        Hostname=host, Region=ctx.region, ExpiresIn=900))
    try:
        with fresh.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone() == (1,), "a fresh admin login after the revoked login was refused did not work"
    finally:
        fresh.close()


def _refused_login(fn) -> set[str]:
    try:
        conn = fn()
    except psycopg.OperationalError as exc:
        return set(re.findall(r"FATAL:  ([^\n]*)", str(exc)))
    conn.close()
    raise AssertionError("expected the login to be refused, but it was accepted")


def _refused_login_within(fn, timeout_s: float) -> set[str]:
    """The FATAL lines of the first refused login; AWS may honour a REVOKE late, never not at all."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            conn = fn()
        except psycopg.OperationalError as exc:
            return set(re.findall(r"FATAL:  ([^\n]*)", str(exc)))
        conn.close()
        if time.monotonic() >= deadline:
            raise AssertionError(f"login after AWS IAM REVOKE was still accepted after {timeout_s}s")
        time.sleep(3)


def _assume(ctx, role_arn: str) -> dict:
    """Credentials for the role; a new role is not assumable until IAM propagates it."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 60
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-dsql-role")["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _delete_role(iam, role_name: str) -> None:
    for fn in (lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="dbconnect"),
               lambda: iam.delete_role(RoleName=role_name)):
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


# ===== helpers =====

_ACTIVE_TIMEOUT_S = 600.0
_CONNECT_TIMEOUT_S = 180.0
_REVOKE_TIMEOUT_S = 60.0


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
