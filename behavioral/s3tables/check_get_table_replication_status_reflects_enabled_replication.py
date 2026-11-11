"""get-table-replication-status-reflects-enabled-replication."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-replication-status-reflects-enabled-replication"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After enabling table replication, GetTableReplicationStatus reports the
    replication as active server-side (destination status begins at 'pending') without
    any explicit trigger call."""
    s3t = ctx.client("s3tables")
    source_arn = _create_table_bucket(ctx)
    dest_arn = _create_table_bucket(ctx)
    role_arn = _create_replication_role(ctx, source_arn, dest_arn)
    namespace = _create_namespace(ctx, source_arn)
    table_arn, _table_name = _create_table(ctx, source_arn, namespace)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}],
    }
    _retry_until(
        lambda: s3t.put_table_replication(tableArn=table_arn, configuration=configuration)
    )

    status_resp = _retry_until(
        lambda: _with_nonempty_destinations(s3t, table_arn),
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert status_resp["sourceTableArn"] == table_arn, (
        f"expected sourceTableArn {table_arn!r}, got {status_resp.get('sourceTableArn')!r}"
    )
    destinations = status_resp["destinations"]
    assert len(destinations) == 1, f"expected exactly 1 destination, got {destinations!r}"
    assert destinations[0]["destinationTableBucketArn"] == dest_arn, (
        f"expected destination {dest_arn!r}, got {destinations[0]!r}"
    )
    # a freshly-enabled replication destination reports a status server-side
    # (pending/in-progress or already completed) without any explicit trigger call --
    # FAILED is excluded on purpose: this is the modelled enum's full range, and a
    # correctly-permissioned setup (the role above holds exactly the actions AWS's own
    # replication docs list) must never land there. Accepting FAILED here would make the
    # assertion true for every target, including one that always reports failure.
    status = destinations[0]["replicationStatus"].upper()
    assert status in ("PENDING", "COMPLETED"), (
        f"expected replicationStatus PENDING or COMPLETED for a correctly-permissioned "
        f"replication setup, got {status!r}"
    )


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn):
    s3t = ctx.client("s3tables")
    namespace = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace))
    return namespace


def _create_table(ctx, bucket_arn, namespace):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    resp = s3t.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace,
        name=name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return resp["tableARN"], name


def _create_replication_role(ctx, source_bucket_arn, dest_bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3trepl-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    perms = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3tables:GetTable",
                        "s3tables:GetTableMetadataLocation",
                        "s3tables:GetTableMaintenanceConfiguration",
                        "s3tables:GetTableData",
                    ],
                    "Resource": f"{source_bucket_arn}/table/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3tables:ListTables"],
                    "Resource": source_bucket_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3tables:CreateTable", "s3tables:CreateNamespace"],
                    "Resource": dest_bucket_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3tables:PutTableData",
                        "s3tables:GetTableData",
                        "s3tables:UpdateTableMetadataLocation",
                        "s3tables:PutTableMaintenanceConfiguration",
                    ],
                    "Resource": f"{dest_bucket_arn}/table/*",
                },
            ],
        }
    )
    policy_name = ctx.unique_name("sim2real-s3trepl-pol-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=perms)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _retry_until(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ForbiddenException", "NotFoundException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
            continue
        if result is not None:
            return result
        last_exc = AssertionError("condition never became true")
        time.sleep(interval_s)
    raise last_exc


def _with_nonempty_destinations(s3t, table_arn):
    resp = s3t.get_table_replication_status(tableArn=table_arn)
    if resp.get("destinations"):
        return resp
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
