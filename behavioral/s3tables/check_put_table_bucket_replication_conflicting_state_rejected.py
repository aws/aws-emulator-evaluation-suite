"""put-table-bucket-replication-conflicting-state-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-replication-conflicting-state-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]

MSG_NO_REPLICATION = "The specified replication configuration does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketReplication with a versionToken while no replication config exists fails with
    NotFoundException (there is nothing to match the token against) and creates nothing; the same config
    without a token then succeeds."""
    s3tables = ctx.client("s3tables")
    source_arn = _create_table_bucket(ctx, s3tables)
    dest_arn = _create_table_bucket(ctx, s3tables)
    role_arn = _create_replication_role(ctx, source_arn, [dest_arn])

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}],
    }

    code, message = _error(
        lambda: s3tables.put_table_bucket_replication(
            tableBucketARN=source_arn,
            versionToken="sim2real-bogus-version-token",
            configuration=configuration,
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == MSG_NO_REPLICATION, f"message={message!r}"

    # Effect absent: the rejected call must not have created a configuration.
    still_missing, missing_message = _error(
        lambda: s3tables.get_table_bucket_replication(tableBucketARN=source_arn)
    )
    assert still_missing == "NotFoundException", (
        f"expected no replication configuration after rejected put, got {still_missing}"
    )
    assert missing_message == MSG_NO_REPLICATION, f"message={missing_message!r}"

    # Positive control: the same configuration without a version precondition
    # succeeds (allow for brief IAM propagation delay on the freshly created role).
    _put_bucket_replication_with_retry(s3tables, source_arn, configuration)
    ctx.on_cleanup(lambda: _delete_bucket_replication_ignore(s3tables, source_arn))
    got = s3tables.get_table_bucket_replication(tableBucketARN=source_arn)
    assert got["configuration"]["role"] == role_arn, (
        f"expected role {role_arn}, got {got['configuration'].get('role')}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_replication_role(ctx, source_bucket_arn: str, dest_bucket_arns: list[str]) -> str:
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                "Resource": [source_bucket_arn, f"{source_bucket_arn}/table/*"],
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


def _put_bucket_replication_with_retry(s3tables, bucket_arn: str, configuration: dict) -> None:
    """Retries on AccessDeniedException to tolerate IAM role-propagation delay
    for a role that was just created."""
    deadline = time.monotonic() + 45
    last_code = None
    while time.monotonic() < deadline:
        try:
            s3tables.put_table_bucket_replication(
                tableBucketARN=bucket_arn, configuration=configuration
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"put_table_bucket_replication never succeeded, last error: {last_code}")


def _delete_bucket_replication_ignore(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket_replication(tableBucketARN=bucket_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
