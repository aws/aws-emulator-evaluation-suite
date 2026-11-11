"""concurrent-put-table-replication-conflict-detected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-table-replication-conflict-detected"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTableReplication with a stale versionToken is refused with ConflictException and the exact
    message, and the configuration keeps the writer that presented the current token."""
    s3tables = ctx.client("s3tables")
    source_arn = _create_table_bucket(ctx, s3tables)
    dest_a = _create_table_bucket(ctx, s3tables)
    dest_b = _create_table_bucket(ctx, s3tables)
    namespace = _create_namespace(ctx, s3tables, source_arn)
    _table_name, table_arn = _create_table(ctx, s3tables, source_arn, namespace)
    role_arn = _create_replication_role(ctx, source_arn, table_arn, [dest_a, dest_b])

    config_a = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_a}]}]}
    config_b = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_b}]}]}

    first = _put_table_replication_with_retry(s3tables, table_arn, config_a)
    ctx.on_cleanup(lambda: _delete_table_replication_ignore(s3tables, table_arn))
    assert first == "ok", f"expected the first PutTableReplication to succeed, got {first}"
    stale_token = s3tables.get_table_replication(tableArn=table_arn)["versionToken"]

    s3tables.put_table_replication(tableArn=table_arn, versionToken=stale_token, configuration=config_b)

    try:
        s3tables.put_table_replication(tableArn=table_arn, versionToken=stale_token, configuration=config_a)
        raise AssertionError("PutTableReplication with a stale versionToken was accepted")
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "ConflictException", f"expected ConflictException, got {error}"
        assert error.get("Message") == _STALE_TOKEN_MESSAGE, f"unexpected stale-token message: {error}"

    final = s3tables.get_table_replication(tableArn=table_arn)
    destinations = final["configuration"]["rules"][0]["destinations"]
    assert [d["destinationTableBucketARN"] for d in destinations] == [dest_b], (
        f"expected the current-token writer's destination {dest_b} only, got {destinations}"
    )
    assert final["versionToken"] != stale_token, "the accepted update did not advance the versionToken"


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _ident_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    return re.sub(r"[^0-9a-z_]", "_", raw)[:255]


_STALE_TOKEN_MESSAGE = "The specified version token does not match the configuration."

_SIM2REAL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name, tags=_SIM2REAL_TAGS)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, s3tables, bucket_arn: str) -> str:
    ns = _ident_name(ctx, "sim2real_ns_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))
    return ns


def _create_table(ctx, s3tables, bucket_arn: str, namespace: str, fmt: str = "ICEBERG"):
    name = _ident_name(ctx, "sim2real_tbl_")
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format=fmt, tags=_SIM2REAL_TAGS
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return name, resp["tableARN"]


def _create_replication_role(ctx, source_bucket_arn: str, source_table_arn: str, dest_bucket_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3trepl-")[:64]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _SIM2REAL_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    dest_resources: list[str] = []
    for arn in dest_bucket_arns:
        dest_resources.extend([arn, f"{arn}/table/*"])

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:GetTable",
                    "s3tables:GetTableMetadataLocation",
                    "s3tables:GetTableData",
                    "s3tables:GetTableMaintenanceConfiguration",
                    "s3tables:ListTables",
                ],
                "Resource": [source_bucket_arn, source_table_arn],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:CreateTable",
                    "s3tables:CreateNamespace",
                    "s3tables:PutTableData",
                    "s3tables:GetTableData",
                    "s3tables:UpdateTableMetadataLocation",
                    "s3tables:PutTableMaintenanceConfiguration",
                ],
                "Resource": dest_resources,
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-s3trepl-pol-")[:64]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _put_table_replication_with_retry(s3tables, table_arn: str, configuration: dict) -> str:
    """Retries on AccessDeniedException to tolerate IAM role-propagation delay
    for a role that was just created, then reports the outcome code."""
    deadline = time.monotonic() + 45
    last_code = None
    while time.monotonic() < deadline:
        try:
            s3tables.put_table_replication(tableArn=table_arn, configuration=configuration)
            return "ok"
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                return last_code
            time.sleep(3)
    return last_code or "timed_out"


def _delete_table_replication_ignore(s3tables, table_arn: str) -> None:
    try:
        current = s3tables.get_table_replication(tableArn=table_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    try:
        s3tables.delete_table_replication(
            tableArn=table_arn, versionToken=current["versionToken"]
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
