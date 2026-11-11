"""s3-bucket-policy-allows-dynamodb-export-service-principal-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-bucket-policy-allows-dynamodb-export-service-principal-positive"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """An export by a role with only dynamodb:ExportTableToPointInTime ends COMPLETED with objects
    written when the bucket policy grants that role's ARN s3:PutObject, s3:AbortMultipartUpload and
    s3:PutObjectAcl: the resource policy alone authorizes the write."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-ddbbp-")
    table_arn = _create_table(ctx, table_name)
    _enable_pitr(ctx, table_name)
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-0"}})

    bucket = ctx.unique_name("sim2real-ddbbp-dst-")
    _create_bucket(ctx, bucket)

    role_arn = _create_export_only_role(ctx, table_arn, name_hint="ddbbp-role")

    _call_with_retry(
        lambda: s3.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowExportRoleWrite",
                            "Effect": "Allow",
                            "Principal": {"AWS": role_arn},
                            "Action": ["s3:PutObject", "s3:AbortMultipartUpload", "s3:PutObjectAcl"],
                            "Resource": f"arn:aws:s3:::{bucket}/*",
                        }
                    ],
                }
            ),
        ),
        # a bucket policy naming a just-created role's ARN is rejected until IAM propagation
        # converges -- retry within the window rather than asserting on it.
        retry_codes={"MalformedPolicy"},
        timeout_s=60,
    )

    role_ddb = _assume_role_client(ctx, role_arn, "dynamodb")
    export_desc = _call_with_retry(
        lambda: role_ddb.export_table_to_point_in_time(
            TableArn=table_arn, S3Bucket=bucket, ExportFormat="DYNAMODB_JSON"
        ),
        retry_codes={"AccessDeniedException"},
        timeout_s=90,
    )["ExportDescription"]

    final = _wait_export_terminal(ctx, export_desc["ExportArn"], timeout_s=900)
    assert final["ExportStatus"] == "COMPLETED", (
        f"export authorized solely by bucket policy should COMPLETE, got "
        f"{final['ExportStatus']} failure={final.get('FailureCode')}/{final.get('FailureMessage')}"
    )
    listing = s3.list_objects_v2(Bucket=bucket, Prefix="AWSDynamoDB/")
    assert listing.get("KeyCount", 0) > 0, "export completed but wrote no objects"


def _create_table(ctx: Any, table_name: str) -> str:
    ddb = ctx.client("dynamodb")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return ddb.describe_table(TableName=table_name)["Table"]["TableArn"]


def _enable_pitr(ctx: Any, table_name: str, timeout_s: float = 60.0) -> None:
    ddb = ctx.client("dynamodb")
    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        if status == "ENABLED":
            return
        time.sleep(2)
    raise AssertionError("PITR never reached ENABLED")


def _wait_export_terminal(ctx: Any, export_arn: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = ddb.describe_export(ExportArn=export_arn)["ExportDescription"]
        if desc["ExportStatus"] != "IN_PROGRESS":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"export did not reach a terminal state within {timeout_s}s: {desc}")


def _create_bucket(ctx: Any, name: str) -> str:
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_export_only_role(ctx: Any, table_arn: str, name_hint: str) -> str:
    """Create a role assumable by the calling (test) identity's own account, scoped
    ONLY to dynamodb:ExportTableToPointInTime on the table -- no S3 permission."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-{name_hint}-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    policy_name = "export-only-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:ExportTableToPointInTime", "Resource": table_arn}
                ],
            }
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _assume_role_client(ctx: Any, role_arn: str, service: str, timeout_s: float = 90.0) -> Any:
    from botocore.exceptions import ClientError

    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
            break
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    if creds is None:
        raise last_exc

    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _call_with_retry(fn, retry_codes: set, timeout_s: float = 60.0, interval_s: float = 3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
