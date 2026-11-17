"""update-column-statistics-task-settings-unknown-table-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-column-statistics-task-settings-unknown-table-rejected"
GROUP = "state-machine"
SERVICES = ["glue", "iam", "s3"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        for pol_name in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _glue_role_arn(ctx, iam, bucket):
    """An IAM role Glue can assume, with read access to ``bucket``, torn down by this check."""
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    # AWSGlueServiceRole only grants S3 access under the "aws-glue-*" naming convention, so a
    # differently-named bucket needs an explicit grant.
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-bucket-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    return resp["Role"]["Arn"]


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _retry_iam_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    """A freshly-created role can lag IAM propagation; retry on the resulting ClientError,
    bounded by a deadline, rather than a blind sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateColumnStatisticsTaskSettings on a database/table with no stored settings fails
    EntityNotFoundException with the same message GetColumnStatisticsTaskSettings gives, and the
    identical call against a table that really has settings persists its new SampleSize.
    """
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-colstat-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    role = _glue_role_arn(ctx, iam, bucket)

    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real-behav-table-")
    s3.put_object(Bucket=bucket, Key=f"{table_name}/data.csv", Body=b"id\n1\n2\n")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}],
                "Location": f"s3://{bucket}/{table_name}/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    _retry_iam_propagation(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=db_name,
            TableName=table_name,
            Role=role,
            SampleSize=50.0,
            Schedule="cron(0 1 * * ? *)",
        )
    )
    ctx.on_cleanup(
        lambda: glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    )

    missing_table = ctx.unique_name("sim2real-behav-table-missing-")
    code, message = _error(
        lambda: glue.update_column_statistics_task_settings(
            DatabaseName=db_name, TableName=missing_table, Role=role, SampleSize=75.0
        )
    )
    expected_missing = "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist"
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == expected_missing, f"unexpected message for a missing table: {message!r}"

    # Effect absent: the rejected call did not create settings under the missing table.
    code, message = _error(
        lambda: glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=missing_table)
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == expected_missing, f"unexpected message for a missing table: {message!r}"

    # Positive control: the identical call against the real table succeeds.
    glue.update_column_statistics_task_settings(
        DatabaseName=db_name, TableName=table_name, Role=role, SampleSize=75.0
    )
    settings = glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)[
        "ColumnStatisticsTaskSettings"
    ]
    assert settings["SampleSize"] == 75.0, (
        f"expected UpdateColumnStatisticsTaskSettings to persist SampleSize=75.0, "
        f"got {settings.get('SampleSize')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
