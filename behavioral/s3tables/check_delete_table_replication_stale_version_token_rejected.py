"""delete-table-replication-stale-version-token-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-replication-stale-version-token-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableReplication with a stale versionToken is rejected with ConflictException and keeps the
    current configuration; a delete with the current token succeeds, so the refusal is about staleness."""
    s3tables = ctx.client("s3tables")
    source_bucket_arn = _create_table_bucket(ctx, "svt-src")
    dest_bucket_arn = _create_table_bucket(ctx, "svt-dst")
    table = _create_table(ctx, source_bucket_arn, "svt")
    role_arn = _create_replication_role(ctx)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_bucket_arn}]}],
    }
    put1 = _retry_on_access_denied(
        lambda: s3tables.put_table_replication(tableArn=table["arn"], configuration=configuration)
    )
    stale_token = put1["versionToken"]

    # Bump the version so `stale_token` is now out of date.
    put2 = s3tables.put_table_replication(
        tableArn=table["arn"], versionToken=stale_token, configuration=configuration
    )
    current_token = put2["versionToken"]
    assert current_token != stale_token, (
        f"PutTableReplication did not advance the version token: still {stale_token!r} after a "
        "second successful put"
    )

    code, message = _error(
        lambda: s3tables.delete_table_replication(tableArn=table["arn"], versionToken=stale_token)
    )
    assert code == "ConflictException", (
        f"DeleteTableReplication with a superseded versionToken returned {code!r}, expected "
        '"ConflictException"'
    )
    assert message == "Provided version token does not match the table version token.", message

    # Effect absent: the configuration is still there, still at the current version.
    got = s3tables.get_table_replication(tableArn=table["arn"])
    assert got["versionToken"] == current_token, (
        f"a rejected DeleteTableReplication changed the version token to "
        f"{got['versionToken']!r}, expected it to stay at {current_token!r}"
    )

    # Positive control: deleting with the correct, current token succeeds.
    s3tables.delete_table_replication(tableArn=table["arn"], versionToken=current_token)
    final_code, final_message = _error(lambda: s3tables.get_table_replication(tableArn=table["arn"]))
    assert final_code == "NotFoundException", (
        f"GetTableReplication after a successful DeleteTableReplication returned {final_code!r}, "
        'expected "NotFoundException"'
    )
    assert final_message == "The specified replication configuration does not exist.", final_message


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _create_table_bucket(ctx, suffix: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_table(ctx, bucket_arn: str, prefix: str) -> dict[str, str]:
    s3tables = ctx.client("s3tables")
    namespace = _sanitize(ctx.unique_name(f"sim2real_{prefix}_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(
        lambda: _safe(
            lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        )
    )
    name = _sanitize(ctx.unique_name(f"sim2real_{prefix}_tbl_"))
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    table_arn = resp["tableARN"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
        )
    )
    return {"arn": table_arn, "namespace": namespace, "name": name}


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real s3tables replication test role",
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = "sim2real-s3t-repl-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3tables:*"], "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _retry_on_access_denied(fn, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ForbiddenException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
