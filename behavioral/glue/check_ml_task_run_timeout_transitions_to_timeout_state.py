"""ml-task-run-timeout-transitions-to-timeout-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ml-task-run-timeout-transitions-to-timeout-state"
GROUP = "visibility-timeout-ttl"
SERVICES = ["glue"]


# timing:real-time — workflow: 60 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A labeling-set generation task run on an ML transform with Timeout=1 minute and a readable
    input table ends with GetMLTaskRun Status TIMEOUT.
    """
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_service_role(ctx)
    db_name, table_name = _create_glue_table(ctx, bucket)

    transform_id = _retry_iam_propagation(
        lambda: glue.create_ml_transform(
            Name=ctx.unique_name("sim2real-glue-mlt-"),
            InputRecordTables=[{"DatabaseName": db_name, "TableName": table_name}],
            Parameters={
                "TransformType": "FIND_MATCHES",
                "FindMatchesParameters": {"PrimaryKeyColumnName": "id"},
            },
            Role=role_arn,
            WorkerType="G.1X",
            NumberOfWorkers=2,
            Timeout=1,  # minutes -- minimum allowed; Glue's Spark cold-start
            # for a labeling-set generation run commonly exceeds this, forcing
            # a TIMEOUT before the job would otherwise finish on the (real,
            # small) input data.
            MaxRetries=0,
            Tags={"sim2real": CHECK},
        )
    )["TransformId"]
    ctx.on_cleanup(lambda: _safe_call(glue.delete_ml_transform, TransformId=transform_id))

    task_run_id = glue.start_ml_labeling_set_generation_task_run(
        TransformId=transform_id,
        OutputS3Path=f"s3://{bucket}/labels/",
    )["TaskRunId"]

    final_status = _poll_until(
        lambda: glue.get_ml_task_run(TransformId=transform_id, TaskRunId=task_run_id)["Status"],
        lambda status: status in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT"),
        timeout_s=900,
        interval_s=15,
    )
    assert final_status == "TIMEOUT", (
        f"expected the 1-minute-timeout MLTaskRun to reach TIMEOUT, got {final_status}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _retry_iam_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _safe_call(fn, **kwargs):
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    glue_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=glue_policy_arn)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)

    def _cleanup():
        for policy_arn in (glue_policy_arn, s3_policy_arn):
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
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


def _create_glue_table(ctx, bucket):
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    db_name = ctx.unique_name("sim2real-glue-db-")
    table_name = ctx.unique_name("sim2real-glue-tbl-")

    rows = [(i, f"customer-{i}", f"cat{i % 4}") for i in range(1, 31)]
    body = "\n".join(",".join(str(v) for v in row) for row in rows) + "\n"
    s3.put_object(Bucket=bucket, Key="data/data.csv", Body=body.encode())

    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe_call(glue.delete_database, Name=db_name))

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "int"},
                    {"Name": "name", "Type": "string"},
                    {"Name": "category", "Type": "string"},
                ],
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: _safe_call(glue.delete_table, DatabaseName=db_name, Name=table_name))
    return db_name, table_name


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-mlt-")

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
