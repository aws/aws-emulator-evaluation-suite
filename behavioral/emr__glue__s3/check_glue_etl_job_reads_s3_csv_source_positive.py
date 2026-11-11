"""glue-etl-job-reads-s3-csv-source-positive."""
from __future__ import annotations

import json
import textwrap
import time

from behavioral_harness import tags

CHECK = "glue-etl-job-reads-s3-csv-source-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]

_ROW_COUNT = 5

_SCRIPT = textwrap.dedent(
    """\
    import sys
    from awsglue.utils import getResolvedOptions
    from awsglue.context import GlueContext
    from pyspark.context import SparkContext

    args = getResolvedOptions(sys.argv, ["JOB_NAME", "SOURCE_PATH", "OUTPUT_PATH"])
    sc = SparkContext()
    glue_context = GlueContext(sc)

    dyf = glue_context.create_dynamic_frame.from_options(
        connection_type="s3",
        format="csv",
        connection_options={"paths": [args["SOURCE_PATH"]], "recurse": True},
        format_options={"withHeader": True},
        transformation_ctx="datasource0",
    )
    row_count = dyf.toDF().count()
    spark = glue_context.spark_session
    spark.createDataFrame([(str(row_count),)], ["value"]).coalesce(1) \
        .write.mode("overwrite").text(args["OUTPUT_PATH"])
    """
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue ETL job's DynamicFrame read retrieves the exact row count of a CSV S3 source."""
    bucket = _create_bucket(ctx)
    rows = "\n".join(f"{i},name-{i},{i * 1.5}" for i in range(_ROW_COUNT))
    _put_object(ctx, bucket, "data/input.csv", "id,name,amount\n" + rows + "\n")
    _put_object(ctx, bucket, "scripts/read_csv.py", _SCRIPT)

    role_arn = _create_glue_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )
    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    _create_job_with_retry(
        glue,
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "glueetl",
            "ScriptLocation": f"s3://{bucket}/scripts/read_csv.py",
            "PythonVersion": "3",
        },
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        MaxRetries=0,
        Timeout=15,
        Tags={"sim2real": "emr-glue-s3"},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    job_run = _run_job_until_role_propagates(
        ctx,
        glue,
        job_name,
        {
            "--SOURCE_PATH": f"s3://{bucket}/data/input.csv",
            "--OUTPUT_PATH": f"s3://{bucket}/output/read-test/",
        },
    )

    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix="output/read-test/")
    part_keys = [o["Key"] for o in resp.get("Contents", []) if "part-" in o["Key"]]
    assert len(part_keys) >= 1, "expected at least one output part file"
    content = s3.get_object(Bucket=bucket, Key=part_keys[0])["Body"].read().decode().strip()
    assert int(content) == _ROW_COUNT, content


def _bucket_region_kwargs(ctx):
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _put_object(ctx, bucket: str, key: str, body) -> None:
    if isinstance(body, str):
        body = body.encode("utf-8")
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _create_glue_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "emr-glue-s3"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    if extra_statements:
        policy_name = ctx.unique_name("sim2real-glue-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_job_with_retry(glue, timeout_s: float = 60.0, **kwargs) -> None:
    """CreateJob validates synchronously that Glue can assume the role, so it raises
    InvalidInputException while IAM propagation is still in flight; retry until it clears."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_job(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


_TERMINAL_JOB_STATES = {"SUCCEEDED", "FAILED", "TIMEOUT", "ERROR", "STOPPED"}


def _wait_for_job_run(ctx, glue, job_name: str, run_id: str, timeout_s: float = 900.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job_run = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if job_run["JobRunState"] in _TERMINAL_JOB_STATES:
            return job_run
        time.sleep(2)
    raise AssertionError(f"job run {run_id} did not reach a terminal state within {timeout_s}s")


_ROLE_PROPAGATION_MARKER = "should be given assume role permissions"


def _run_job_until_role_propagates(ctx, glue, job_name: str, arguments: dict,
                                    *, propagation_timeout_s: float = 180.0):
    """StartJobRun accepts before Glue actually tries to assume the role: unlike CreateCrawler,
    CreateJob does not validate assumability synchronously, so a role that has not finished IAM
    propagation only fails asynchronously, inside the run's own ErrorMessage. Retry the run itself
    (a fresh JobRunId) until propagation catches up or the window closes. Immediately after such a
    failure, Glue's own concurrent-run slot for the job can lag behind the FAILED state it just
    reported via GetJobRun, so StartJobRun itself can bounce with ConcurrentRunsExceededException;
    that is retried too, on the same deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + propagation_timeout_s
    while True:
        try:
            run_id = glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        job_run = _wait_for_job_run(ctx, glue, job_name, run_id, timeout_s=900)
        if job_run["JobRunState"] == "SUCCEEDED":
            return job_run
        error_message = job_run.get("ErrorMessage") or ""
        if _ROLE_PROPAGATION_MARKER not in error_message or time.monotonic() >= deadline:
            raise AssertionError(f"job run {run_id} did not succeed: {error_message}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
