"""put-table-replication-then-delete-then-get-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-replication-then-delete-then-get-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]

MSG_NO_REPLICATION = "The specified replication configuration does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteTableReplication of a configuration whose role round-tripped, GetTableReplication and a
    second DeleteTableReplication both answer NotFoundException "The specified replication configuration
    does not exist.": the deleted configuration is not returned."""
    s3tables = ctx.client("s3tables")
    source_bucket_arn = _create_table_bucket(ctx, "trepl-src")
    dest_bucket_arn = _create_table_bucket(ctx, "trepl-dst")
    table = _create_table(ctx, source_bucket_arn, "trepl")
    role_arn = _create_replication_role(ctx)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_bucket_arn}]}],
    }
    put_resp = _retry_on_access_denied(
        lambda: s3tables.put_table_replication(tableArn=table["arn"], configuration=configuration)
    )
    version_token = put_resp["versionToken"]

    # Positive control: configuration we just wrote round-trips.
    got = s3tables.get_table_replication(tableArn=table["arn"])
    assert got["configuration"]["role"] == role_arn, (
        f"expected round-tripped replication role {role_arn!r}, "
        f"got {got['configuration']['role']!r}"
    )

    s3tables.delete_table_replication(tableArn=table["arn"], versionToken=version_token)

    code, message = _error(lambda: s3tables.get_table_replication(tableArn=table["arn"]))
    assert code == "NotFoundException", (
        f"expected GetTableReplication on a deleted config to raise NotFoundException, "
        f"got error code {code!r}"
    )
    assert message == MSG_NO_REPLICATION, f"message={message!r}"

    # The config is gone, not merely unreadable: a second delete on the same
    # now-nonexistent config must also refuse rather than silently succeeding.
    redelete_code, redelete_message = _error(
        lambda: s3tables.delete_table_replication(
            tableArn=table["arn"], versionToken=version_token
        )
    )
    assert redelete_code == "NotFoundException", (
        f"expected DeleteTableReplication on an already-deleted config to raise "
        f"NotFoundException, got error code {redelete_code!r}"
    )
    assert redelete_message == MSG_NO_REPLICATION, f"message={redelete_message!r}"


def _ignore_not_found(fn) -> None:
    """Run a teardown call; an already-gone resource (NotFoundException, NoSuchEntity) is the only
    refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "NoSuchEntity"):
            raise


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _create_table_bucket(ctx, suffix: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_table(ctx, bucket_arn: str, prefix: str) -> dict[str, str]:
    s3tables = ctx.client("s3tables")
    namespace = _sanitize(ctx.unique_name(f"sim2real_{prefix}_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        )
    )
    name = _sanitize(ctx.unique_name(f"sim2real_{prefix}_tbl_"))
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    table_arn = resp["tableARN"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
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
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
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
        lambda: _ignore_not_found(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
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
    assert last_exc is not None, (
        "timed out waiting for AccessDenied/ForbiddenException to clear, but never "
        "observed a ClientError to retry on"
    )
    raise last_exc


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
