"""delete-table-bucket-replication-without-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-bucket-replication-without-config-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]

MSG_NO_REPLICATION = "The specified replication configuration does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketReplication on a bucket that never had replication is NotFoundException "The
    specified replication configuration does not exist.", the code GetTableBucketReplication gives too,
    while after a put the same delete succeeds and the get answers NotFoundException again."""
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-repl-")
    bucket_arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=bucket_arn))

    code, message = _error(lambda: s3t.delete_table_bucket_replication(tableBucketARN=bucket_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == MSG_NO_REPLICATION, message

    # effect absent: the rejected delete did not fabricate a replication configuration
    absent_code, absent_message = _error(lambda: s3t.get_table_bucket_replication(tableBucketARN=bucket_arn))
    assert absent_code == "NotFoundException", f"expected NotFoundException, got {absent_code!r}"
    assert absent_message == MSG_NO_REPLICATION, absent_message

    # positive control: the bucket itself remains fully functional
    described = s3t.get_table_bucket(tableBucketARN=bucket_arn)
    assert described["arn"] == bucket_arn, f"expected arn {bucket_arn!r}, got {described['arn']!r}"
    assert described["name"] == name, f"expected name {name!r}, got {described['name']!r}"

    # positive control: once a real configuration exists on this same bucket, the
    # identical DeleteTableBucketReplication call succeeds rather than being rejected
    dest_arn = _create_table_bucket(ctx)
    role_arn = _create_replication_role(ctx, bucket_arn, dest_arn)
    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}],
    }
    put_resp = _retry_until(
        lambda: s3t.put_table_bucket_replication(tableBucketARN=bucket_arn, configuration=configuration)
    )
    s3t.delete_table_bucket_replication(
        tableBucketARN=bucket_arn, versionToken=put_resp["versionToken"]
    )

    # effect: the removed configuration reads back the same as never-configured
    reabsent_code, reabsent_message = _error(lambda: s3t.get_table_bucket_replication(tableBucketARN=bucket_arn))
    assert reabsent_code == "NotFoundException", f"expected NotFoundException, got {reabsent_code!r}"
    assert reabsent_message == MSG_NO_REPLICATION, reabsent_message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-repl-dst-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
