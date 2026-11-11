"""put-and-get-table-replication."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-and-get-table-replication"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableReplication configures table-level replication that is returned unchanged
    by GetTableReplication."""
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
    put_resp = _retry_until(
        lambda: s3t.put_table_replication(tableArn=table_arn, configuration=configuration)
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: s3t.delete_table_replication(
                tableArn=table_arn, versionToken=put_resp["versionToken"]
            )
        )
    )
    # the exact status vocabulary for the Put response is not pinned by docs; what
    # matters for this state-machine check is that some non-empty status is reported
    # and that the configuration itself round-trips exactly through Get below
    assert isinstance(put_resp["status"], str) and put_resp["status"] != "", (
        f"expected a non-empty string status on PutTableReplication, got {put_resp.get('status')!r}"
    )

    get_resp = s3t.get_table_replication(tableArn=table_arn)
    assert get_resp["versionToken"] == put_resp["versionToken"], (
        f"expected GetTableReplication versionToken {put_resp['versionToken']!r} "
        f"(from the Put response) to be unchanged, got {get_resp['versionToken']!r}"
    )
    cfg = get_resp["configuration"]
    assert cfg["role"] == role_arn, f"expected replication role {role_arn!r}, got {cfg.get('role')!r}"
    assert cfg["rules"][0]["destinations"][0]["destinationTableBucketARN"] == dest_arn, (
        f"expected replication destination {dest_arn!r}, "
        f"got {cfg['rules'][0]['destinations'][0].get('destinationTableBucketARN')!r}"
    )


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
