"""iam-role-trusts-glue-service-principal-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trusts-glue-service-principal-positive"
GROUP = "iam-trust"
SERVICES = ["glue", "sqs"]

_SCRIPT = """
import sys
import boto3


def _arg(flag):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


bucket = _arg("--marker_bucket")
key = _arg("--marker_key")
region = _arg("--region")
s3 = boto3.client("s3", region_name=region)
s3.put_object(Bucket=bucket, Key=key, Body=b"ran")
print("marker written")
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting only glue.amazonaws.com is actually assumed by AWS Glue
    when it runs a job (StartJobRun succeeds end-to-end), proving the trust
    document is not just stored but enforced/used by the Glue backend.
    """
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    role_name = ctx.unique_name("sim2real-glue-trust-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )

    bucket = _create_aws_glue_bucket(ctx)
    script_key = "script.py"
    ctx.client("s3").put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT.encode())

    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "pythonshell",
            "PythonVersion": "3.9",
            "ScriptLocation": f"s3://{bucket}/{script_key}",
        },
        MaxCapacity=0.0625,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    marker_key = "marker.txt"
    # IAM trust propagation to Glue is eventually consistent: a run started too soon
    # fails at execution time with "should be given assume role permissions for Glue
    # Service", not with an exception from StartJobRun itself. Retry the whole
    # start-and-poll cycle on that specific transient error; any other failure (or
    # exhausting the retry budget) is a real defect and must fail loudly.
    final = _run_job_until_role_trusted(
        glue, job_name, {"--marker_bucket": bucket, "--marker_key": marker_key, "--region": ctx.region}
    )
    assert final["JobRunState"] == "SUCCEEDED", (
        f"job run did not succeed: {final.get('JobRunState')} / {final.get('ErrorMessage')}"
    )
    # The script only reaches its put_object call if Glue actually assumed
    # the role and started the process; the marker's presence is proof of that.
    ctx.client("s3").head_object(Bucket=bucket, Key=marker_key)


def _create_aws_glue_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    # AWSGlueServiceRole only grants s3:GetObject/PutObject on buckets whose
    # name matches "aws-glue-*", so the script/marker bucket must too.
    bucket = ctx.unique_name("aws-glue-sim2real-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _start_job_run_with_retry(glue, job_name: str, arguments: dict[str, str], deadline: float, interval_s: float) -> str | None:
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as exc:  # ConcurrentRunsExceededException right after a prior run's slot frees up
            if "ConcurrentRunsExceeded" not in type(exc).__name__:
                raise
            time.sleep(interval_s)
    return None


def _run_job_until_role_trusted(
    glue, job_name: str, arguments: dict[str, str], timeout_s: float = 180.0, interval_s: float = 20.0
) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while True:
        run_id = _start_job_run_with_retry(glue, job_name, arguments, deadline, interval_s)
        if run_id is None:
            raise AssertionError(f"start_job_run kept hitting ConcurrentRunsExceeded for {timeout_s}s")
        last = _poll_job_run_terminal(glue, job_name, run_id, timeout_s=480)
        if last["JobRunState"] == "SUCCEEDED":
            return last
        if "assume role" not in (last.get("ErrorMessage") or "").lower():
            return last  # a different failure is a real defect, not propagation
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


def _poll_job_run_terminal(glue, job_name: str, run_id: str, timeout_s: float = 480.0) -> dict:
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if last["JobRunState"] in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"job run never reached a terminal state within {timeout_s}s: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
