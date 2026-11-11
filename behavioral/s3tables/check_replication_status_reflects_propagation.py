"""replication-status-reflects-propagation."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "replication-status-reflects-propagation"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After table replication is put, GetTableReplication's destination (destinationTableBucketARN) has no
    replicationStatus, while GetTableReplicationStatus reports the source table ARN and, under
    destinationTableBucketArn, a replicationStatus that reaches completed for the empty new table."""
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

    # The static configuration view names the destination bucket but carries no
    # per-destination replication status field.
    static_view = s3t.get_table_replication(tableArn=table_arn)
    static_dest = static_view["configuration"]["rules"][0]["destinations"][0]
    assert static_dest["destinationTableBucketARN"] == dest_bucket_arn, (
        f"expected static config destination {dest_bucket_arn!r}, got {static_dest!r}"
    )
    assert "replicationStatus" not in static_dest, (
        f"static config destination unexpectedly carries a replicationStatus: {static_dest!r}"
    )

    status = _poll_until(
        probe=lambda: s3t.get_table_replication_status(tableArn=table_arn),
        # The destinations array itself populates asynchronously -- it is not
        # guaranteed to be there the instant PutTableReplication returns -- so an
        # empty list is "not yet", not a shape error.
        predicate=lambda resp: bool(resp.get("destinations"))
        and resp["destinations"][0]["replicationStatus"].lower() == "completed",
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert status["sourceTableArn"] == table_arn, (
        f"expected sourceTableArn {table_arn!r}, got {status.get('sourceTableArn')!r}"
    )
    assert status["destinations"][0]["destinationTableBucketArn"] == dest_bucket_arn, (
        f"expected status destination {dest_bucket_arn!r}, got {status['destinations'][0]!r}"
    )
    assert status["destinations"][0]["replicationStatus"].lower() == "completed", (
        f"expected replicationStatus completed, got {status['destinations'][0]!r}"
    )


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
    assert last_exc is not None, "retry loop exited without ever calling fn()"
    raise last_exc


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
