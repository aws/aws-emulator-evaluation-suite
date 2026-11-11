"""glue-job-bookmark-persists-processed-s3-keys-positive."""
from __future__ import annotations

import json
import textwrap
import time

from behavioral_harness import tags

CHECK = "glue-job-bookmark-persists-processed-s3-keys-positive"
GROUP = "state-tracking"
SERVICES = ["emr", "glue", "s3"]

_SCRIPT = textwrap.dedent(
    """\
    import sys
    import boto3
    from awsglue.utils import getResolvedOptions
    from awsglue.context import GlueContext
    from awsglue.job import Job
    from pyspark.context import SparkContext

    args = getResolvedOptions(sys.argv, ["JOB_NAME", "SOURCE_PATH", "OUTPUT_PATH"])
    sc = SparkContext()
    glue_context = GlueContext(sc)
    job = Job(glue_context)
    job.init(args["JOB_NAME"], args)

    dyf = glue_context.create_dynamic_frame.from_options(
        connection_type="s3",
        format="csv",
        connection_options={"paths": [args["SOURCE_PATH"]], "recurse": True},
        format_options={"withHeader": True},
        transformation_ctx="bookmarked_source",
    )
    row_count = dyf.toDF().count()
    bucket, key = args["OUTPUT_PATH"][len("s3://"):].split("/", 1)
    boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=str(row_count).encode())
    job.commit()
    """
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Glue job bookmarks skip already-processed S3 source keys on a subsequent run."""
    bucket = _create_bucket(ctx)
    source_prefix = "bookmark-data/"
    _put_object(ctx, bucket, source_prefix + "file1.csv", "id,name\n1,a\n2,b\n3,c\n")  # 3 rows
    _put_object(ctx, bucket, "scripts/bookmark.py", _SCRIPT)

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
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "glueetl",
            "ScriptLocation": f"s3://{bucket}/scripts/bookmark.py",
            "PythonVersion": "3",
        },
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        MaxRetries=0,
        Timeout=15,
        DefaultArguments={"--job-bookmark-option": "job-bookmark-enable"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    ctx.on_cleanup(lambda: glue.reset_job_bookmark(JobName=job_name))

    source_path = f"s3://{bucket}/{source_prefix}"
    run1 = _start_job_run_retrying_role_propagation(
        ctx, glue, job_name,
        {"--SOURCE_PATH": source_path, "--OUTPUT_PATH": f"s3://{bucket}/output/run1/count.txt"},
    )
    assert run1["JobRunState"] == "SUCCEEDED", run1.get("ErrorMessage")
    run1_count = _read_single_output(ctx, bucket, "output/run1/count.txt")
    assert run1_count == 3, run1_count

    # Add a second file after the first successful (bookmarked) run.
    _put_object(ctx, bucket, source_prefix + "file2.csv", "id,name\n4,d\n5,e\n")  # 2 rows

    run2 = _start_job_run_retrying_role_propagation(
        ctx, glue, job_name,
        {"--SOURCE_PATH": source_path, "--OUTPUT_PATH": f"s3://{bucket}/output/run2/count.txt"},
    )
    assert run2["JobRunState"] == "SUCCEEDED", run2.get("ErrorMessage")
    run2_count = _read_single_output(ctx, bucket, "output/run2/count.txt")

    # With the bookmark honored, run2 only sees the newly-added file2.csv (2 rows), not
    # both files reprocessed (which would total 5 rows).
    assert run2_count == 2, run2_count


def _bucket_region_kwargs(ctx):
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


_TERMINAL_JOB_STATES = {"SUCCEEDED", "FAILED", "TIMEOUT", "ERROR", "STOPPED"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_job_run(ctx, glue, job_name: str, run_id: str, timeout_s: float = 900.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job_run = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if job_run["JobRunState"] in _TERMINAL_JOB_STATES:
            return job_run
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"job run {run_id} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"job run {run_id} did not reach a terminal state within {timeout_s}s")


_ROLE_PROPAGATION_RETRY_S = 90.0


def _start_job_run_retrying_role_propagation(ctx, glue, job_name: str, arguments: dict, timeout_s: float = 900.0):
    """Start the job and poll to terminal, retrying Glue's own IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* a few seconds in, not as a StartJobRun error, and no API confirms the
    freshly-created role has become assumable -- so the bounded retry is on this specific
    terminal-state failure rather than a fixed pre-emptive sleep. Starting a new run right after
    a prior run of the same job reaches a terminal state can also transiently raise
    ConcurrentRunsExceededException while Glue's own accounting catches up; retry that too.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _ROLE_PROPAGATION_RETRY_S
    while True:
        try:
            run_id = glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        job_run = _wait_for_job_run(ctx, glue, job_name, run_id, timeout_s=timeout_s)
        message = job_run.get("ErrorMessage") or ""
        if job_run["JobRunState"] != "FAILED" or "assume role permissions" not in message:
            return job_run
        if time.monotonic() >= deadline:
            return job_run
        time.sleep(2)


def _read_single_output(ctx, bucket: str, key: str) -> int:
    s3 = ctx.client("s3")
    content = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode().strip()
    return int(content)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
