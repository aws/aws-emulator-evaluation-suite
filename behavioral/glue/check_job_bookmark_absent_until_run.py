"""job-bookmark-absent-until-run."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-bookmark-absent-until-run"
GROUP = 'job'
SERVICES = ['glue']

_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_S3_POLICY_NAME = "sim2real-behav-s3-access"

_SCRIPT_BODY = b"""
import sys
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job

args = getResolvedOptions(sys.argv, ["JOB_NAME", "INPUT_PATH", "OUTPUT_PATH"])
sc = SparkContext()
glueContext = GlueContext(sc)
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

datasource = glueContext.create_dynamic_frame.from_options(
    connection_type="s3",
    connection_options={"paths": [args["INPUT_PATH"]]},
    format="csv",
    format_options={"withHeader": True},
    transformation_ctx="datasource0",
)
glueContext.write_dynamic_frame.from_options(
    frame=datasource,
    connection_type="s3",
    connection_options={"path": args["OUTPUT_PATH"]},
    format="csv",
)
job.commit()
"""

_INPUT_CSV = b"id,value\n1,a\n2,b\n"


def _create_bucket(ctx, s3, bucket):
    """S3 bucket for the job's script, input and output, emptied and deleted on cleanup."""
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-behav-check", "Value": CHECK}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _delete_role(iam, name):
    try:
        for pol_name in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=pol_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _glue_role_arn(ctx, bucket):
    """Create a Glue-assumable IAM role with S3 access scoped to `bucket`."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
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
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_MANAGED_POLICY_ARN))
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=name, PolicyName=_S3_POLICY_NAME, PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=_S3_POLICY_NAME))
    return resp["Role"]["Arn"]


def _create_job(ctx, glue, role, bucket):
    """A Spark ETL job whose script performs a bookmark-tracked S3 read; pythonshell jobs have
    no GlueContext/DynamicFrame API and so can never populate a bookmark."""
    name = ctx.unique_name("sim2real-behav-job-")
    glue.create_job(
        Name=name,
        Role=role,
        Command={
            "Name": "glueetl",
            "ScriptLocation": f"s3://{bucket}/scripts/etl.py",
            "PythonVersion": "3",
        },
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        Timeout=15,
        DefaultArguments={
            "--job-bookmark-option": "job-bookmark-enable",
            "--TempDir": f"s3://{bucket}/temp/",
            "--INPUT_PATH": f"s3://{bucket}/input/",
            "--OUTPUT_PATH": f"s3://{bucket}/output/",
        },
        Tags={"sim2real-behav-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_iam_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry fn() while a freshly attached trust/inline policy propagates, since Glue's
    AssumeRole probe fails until it does."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            retryable = (
                "AccessDeniedException",
                "InvalidInputException",
                # the previous attempt's run can hold its concurrency slot briefly
                # after reaching a terminal state.
                "ConcurrentRunsExceededException",
            )
            if code in retryable and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetJobBookmark and ResetJobBookmark raise EntityNotFoundException for a never-run job, since
    bookmarks come from runs; a completed bookmark-tracked run populates GetJobBookmark while a
    sibling never-run job still 404s."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-behav-glue-bookmark-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT_BODY)
    s3.put_object(Bucket=bucket, Key="input/data.csv", Body=_INPUT_CSV)

    role = _glue_role_arn(ctx, bucket)
    job_name = _create_job(ctx, glue, role, bucket)

    expected_message = f"Continuation for job {job_name} not found"
    reset_code, reset_message = _error_code(lambda: glue.reset_job_bookmark(JobName=job_name))
    assert reset_code == "EntityNotFoundException", (
        f"ResetJobBookmark on a never-run job must 404, got {reset_code}"
    )
    assert reset_message == expected_message, (
        f"ResetJobBookmark on a never-run job: expected {expected_message!r}, got {reset_message!r}"
    )
    expected_message = f"Continuation for job {job_name} not found"
    get_code, get_message = _error_code(lambda: glue.get_job_bookmark(JobName=job_name))
    assert get_code == "EntityNotFoundException", (
        f"GetJobBookmark on a never-run job must 404, got {get_code}"
    )
    assert get_message == expected_message, (
        f"GetJobBookmark on a never-run job: expected {expected_message!r}, got {get_message!r}"
    )

    expected_message = "Continuation for job does-not-exist-job not found"
    unknown, unknown_message = _error_code(lambda: glue.get_job_bookmark(JobName="does-not-exist-job"))
    assert unknown == "EntityNotFoundException", (
        f"GetJobBookmark for an unknown job must 404, got {unknown}"
    )
    assert unknown_message == expected_message, (
        f"GetJobBookmark for an unknown job: expected {expected_message!r}, got {unknown_message!r}"
    )

    # A not-yet-propagated AssumeRole fails the run, not StartJobRun, so the whole
    # start-and-wait cycle is retried.
    terminal_states = {"SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"}
    final_run = None
    attempts_deadline = time.monotonic() + 600
    while True:
        run_id = _retry_iam_propagation(lambda: glue.start_job_run(JobName=job_name)["JobRunId"])
        run_deadline = time.monotonic() + 900
        while time.monotonic() < run_deadline:
            final_run = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
            if final_run["JobRunState"] in terminal_states:
                break
            time.sleep(2)
        if final_run["JobRunState"] == "SUCCEEDED":
            break
        error_message = (final_run.get("ErrorMessage") or "").lower()
        propagating = any(
            phrase in error_message
            for phrase in ("assume role", "assumerole", "not authorized")
        )
        if propagating and time.monotonic() < attempts_deadline:
            time.sleep(2)
            continue
        raise AssertionError(
            f"bookmark-tracked run did not reach SUCCEEDED: {final_run['JobRunState']} "
            f"({final_run.get('ErrorMessage')})"
        )

    entry = glue.get_job_bookmark(JobName=job_name)["JobBookmarkEntry"]
    assert entry["JobName"] == job_name, entry
    assert entry["Run"] >= 1, f"expected a populated run number after a completed run, got {entry}"

    # Presence tracks per-job run history: a sibling job that has never run is still 404.
    sibling_job = _create_job(ctx, glue, role, bucket)
    expected_message = f"Continuation for job {sibling_job} not found"
    sibling_code, sibling_message = _error_code(lambda: glue.get_job_bookmark(JobName=sibling_job))
    assert sibling_code == "EntityNotFoundException", (
        f"GetJobBookmark on a sibling never-run job must still 404, got {sibling_code}"
    )
    assert sibling_message == expected_message, (
        f"GetJobBookmark on a sibling never-run job: expected {expected_message!r}, got {sibling_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
