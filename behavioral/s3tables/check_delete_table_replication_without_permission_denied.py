"""delete-table-replication-without-permission-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-replication-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableReplication from a principal with no s3tables permissions is denied with
    AccessDeniedException and leaves the configuration intact; a permitted principal then deletes it."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)
    dest_arn = _create_table_bucket(ctx, s3tables)
    namespace = _create_namespace(ctx, s3tables, bucket_arn)
    _table_name, table_arn = _create_table(ctx, s3tables, bucket_arn, namespace)
    role_arn = _create_replication_role(ctx, table_arn, bucket_arn, dest_arn)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}],
    }
    _put_table_replication_with_retry(s3tables, table_arn, configuration)
    ctx.on_cleanup(lambda: _delete_table_replication_ignore(s3tables, table_arn))

    current = s3tables.get_table_replication(tableArn=table_arn)
    version_token = current["versionToken"]

    restricted, role_name = _restricted_s3tables_client(ctx)
    code, message = _error(
        lambda: restricted.delete_table_replication(
            tableArn=table_arn, versionToken=version_token
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/sim2real-behavioral is not "
        f"authorized to perform: s3tables:DeleteTableReplication on resource: {table_arn} "
        f"because no identity-based policy allows the s3tables:DeleteTableReplication action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the configuration is still there, unchanged.
    still_there = s3tables.get_table_replication(tableArn=table_arn)
    assert still_there["configuration"]["role"] == role_arn, (
        f"expected replication role {role_arn}, got {still_there['configuration']['role']}"
    )

    # Positive control: the properly-permissioned harness principal can delete it.
    s3tables.delete_table_replication(
        tableArn=table_arn, versionToken=still_there["versionToken"]
    )
    gone, gone_message = _error(lambda: s3tables.get_table_replication(tableArn=table_arn))
    assert gone == "NotFoundException", f"replication configuration still present: {gone}"
    expected_gone = "The specified replication configuration does not exist."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _ident_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    return re.sub(r"[^0-9a-z_]", "_", raw)[:255]


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name, tags=_TAGS)["arn"]
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
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format=fmt
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return name, resp["tableARN"]


def _create_replication_role(ctx, source_table_arn: str, source_bucket_arn: str, dest_bucket_arn: str) -> str:
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

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
                "Resource": [dest_bucket_arn, f"{dest_bucket_arn}/table/*"],
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


def _put_table_replication_with_retry(s3tables, table_arn: str, configuration: dict) -> None:
    deadline = time.monotonic() + 45
    last_code = None
    while time.monotonic() < deadline:
        try:
            s3tables.put_table_replication(tableArn=table_arn, configuration=configuration)
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"put_table_replication never succeeded, last error: {last_code}")


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


def _restricted_s3tables_client(ctx):
    """An s3tables client backed by a freshly created IAM role with zero attached
    policies, so every s3tables call is denied by implicit deny; also the role name."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-s3t-noaccess-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deadline = time.monotonic() + 60
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behavioral"
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(3)
    if creds is None:
        raise AssertionError(f"could not assume restricted role: {last_err}")

    client = ctx.client(
        "s3tables",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
