"""delete-table-replication-then-get-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-replication-then-get-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteTableReplication, GetTableReplication and a second delete both answer NotFoundException
    "The specified replication configuration does not exist.": the delete is not repeatable."""
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

    # positive control: the configuration is readable right after being set
    get_resp = s3t.get_table_replication(tableArn=table_arn)
    assert get_resp["configuration"]["role"] == role_arn, (
        f"expected the just-written role {role_arn!r}, got {get_resp['configuration'].get('role')!r}"
    )
    version_token = get_resp["versionToken"]

    s3t.delete_table_replication(tableArn=table_arn, versionToken=version_token)

    code, message = _error(lambda: s3t.get_table_replication(tableArn=table_arn))
    assert code == "NotFoundException", (
        f"expected GetTableReplication to raise NotFoundException after delete, got {code!r}"
    )
    assert message == "The specified replication configuration does not exist.", message

    # mutation on the dead id also fails: the config is fully gone, so a second
    # delete (even with the last-known-good token) must not succeed.
    redelete_code, redelete_message = _error(
        lambda: s3t.delete_table_replication(tableArn=table_arn, versionToken=version_token)
    )
    assert redelete_code == "NotFoundException", (
        f"expected a second DeleteTableReplication on an already-deleted config to be "
        f"rejected with NotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == "The specified replication configuration does not exist.", redelete_message


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name)["arn"]
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
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
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
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
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
