"""put-table-replication-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-table-replication-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3tables"]

MSG_NO_REPLICATION = "The specified replication configuration does not exist."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableReplication persists a config that DeleteTableReplication removes (Get and a second delete
    then fail with NotFoundException), and a fresh Put on the same table succeeds and round-trips again."""
    s3t = ctx.client("s3tables")
    source_bucket_arn = _create_table_bucket(ctx)
    dest_bucket_arn = _create_table_bucket(ctx)
    _create_namespace(ctx, source_bucket_arn, "ns")
    table_arn = _create_table(ctx, source_bucket_arn, "ns", "tbl")
    role_arn = _create_replication_role(ctx)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_bucket_arn}]}],
    }
    _retry_role_propagation(
        lambda: s3t.put_table_replication(tableArn=table_arn, configuration=configuration)
    )

    got = s3t.get_table_replication(tableArn=table_arn)
    assert got["configuration"]["role"] == role_arn, (
        f"expected role {role_arn!r}, got {got['configuration']['role']!r}"
    )
    assert (
        got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
        == dest_bucket_arn
    ), "expected the destination bucket ARN we configured to round-trip through Get"
    version_token = got["versionToken"]

    s3t.delete_table_replication(tableArn=table_arn, versionToken=version_token)

    code, message = _error(lambda: s3t.get_table_replication(tableArn=table_arn))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == MSG_NO_REPLICATION, f"message={message!r}"

    # Mutation on the dead config also fails: a second delete using the same
    # versionToken has nothing left to delete.
    redelete_code, redelete_message = _error(
        lambda: s3t.delete_table_replication(tableArn=table_arn, versionToken=version_token)
    )
    assert redelete_code == "NotFoundException", (
        f"expected NotFoundException re-deleting an already-deleted config, got {redelete_code}"
    )
    assert redelete_message == MSG_NO_REPLICATION, f"message={redelete_message!r}"

    # Reusable: the table itself is untouched by the replication delete, so a fresh
    # Put on it succeeds and round-trips exactly like the first one did.
    recreated = _retry_role_propagation(
        lambda: s3t.put_table_replication(tableArn=table_arn, configuration=configuration)
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: s3t.delete_table_replication(
                tableArn=table_arn, versionToken=recreated["versionToken"]
            )
        )
    )
    assert recreated["versionToken"] != version_token, (
        "expected the recreated config to carry a fresh versionToken, not the deleted one"
    )
    got_again = s3t.get_table_replication(tableArn=table_arn)
    assert got_again["configuration"]["role"] == role_arn, (
        f"expected role {role_arn!r} on the recreated config, got "
        f"{got_again['configuration']['role']!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn: str, ns: str) -> None:
    s3t = ctx.client("s3tables")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))


def _create_table(ctx, bucket_arn: str, ns: str, name: str) -> str:
    s3t = ctx.client("s3tables")
    arn = s3t.create_table(
        tableBucketARN=bucket_arn, namespace=ns, name=name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=ns, name=name))
    return arn


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3tables-replication",
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-replication")
    )
    return role_arn


def _retry_role_propagation(
    fn: Callable[[], Any], *, timeout_s: float = 90.0, interval_s: float = 5.0
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ForbiddenException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
