"""glue-job-writes-output-to-s3-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-job-writes-output-to-s3-positive"
GROUP = "resource-binding"
SERVICES = ["athena", "glue", "s3"]

_GLUE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_GLUE_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"

_SCRIPT = """
import sys
import boto3

def _resolve(argv):
    out = {}
    it = iter(argv[1:])
    for tok in it:
        if tok.startswith("--"):
            out[tok[2:]] = next(it, "")
    return out

args = _resolve(sys.argv)
s3 = boto3.client("s3")
body = s3.get_object(Bucket=args["src_bucket"], Key=args["src_key"])["Body"].read()
transformed = body.decode("utf-8").upper().encode("utf-8")
s3.put_object(Bucket=args["dst_bucket"], Key=args["dst_key"], Body=transformed)
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job configured to run under an execution role does not just report
    SUCCEEDED as a formality: it must actually read the source object from S3 and
    write a transformed object to the configured destination in S3."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-gluejob-")
    _create_bucket(ctx, s3, bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    script_key = "scripts/job.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT.encode("utf-8"))

    src_key = "input/source.txt"
    src_body = b"hello from glue job output binding test"
    s3.put_object(Bucket=bucket, Key=src_key, Body=src_body)
    dst_key = "output/result.txt"

    role_name = ctx.unique_name("sim2real-gluejob-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_GLUE_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="rw-bucket", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="rw-bucket"))

    job_name = ctx.unique_name("sim2real-gluejob-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "pythonshell",
            "ScriptLocation": f"s3://{bucket}/{script_key}",
            "PythonVersion": "3.9",
        },
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    arguments = {
        "--src_bucket": bucket,
        "--src_key": src_key,
        "--dst_bucket": bucket,
        "--dst_key": dst_key,
    }
    run_id = _start_job_run_with_retry(glue, job_name, arguments)
    job_run = _wait_for_job_run(glue, job_name, run_id, timeout_s=360)
    state = (job_run or {}).get("JobRunState")

    for _attempt in range(2):
        if state == "SUCCEEDED":
            break
        error = (job_run or {}).get("ErrorMessage") or ""
        if "assume role permissions" not in error:
            # Not the known IAM-propagation window (a freshly created role
            # briefly not assumable by Glue) -- a genuine failure, so stop
            # retrying and let the assertion below report it.
            break
        time.sleep(2)
        run_id = _start_job_run_with_retry(glue, job_name, arguments)
        job_run = _wait_for_job_run(glue, job_name, run_id, timeout_s=360)
        state = (job_run or {}).get("JobRunState")

    assert state == "SUCCEEDED", (
        f"Glue job run ended in state {state!r}, expected SUCCEEDED "
        f"({(job_run or {}).get('ErrorMessage')!r})"
    )

    result = s3.get_object(Bucket=bucket, Key=dst_key)["Body"].read()
    assert result == src_body.upper(), f"output object content mismatch: {result!r}"


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _start_job_run_with_retry(glue, job_name: str, arguments: dict, retries: int = 4, delay: int = 15) -> str:
    """Glue can briefly report ConcurrentRunsExceededException right after a
    prior run on the same job reaches a terminal state (its "currently
    running" bookkeeping trails the JobRun status by a few seconds); retry
    through that window instead of failing outright."""
    from botocore.exceptions import ClientError

    for attempt in range(retries + 1):
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConcurrentRunsExceededException" and attempt < retries:
                time.sleep(delay)
                continue
            raise


def _wait_for_job_run(glue, job_name: str, run_id: str, timeout_s: int = 360) -> dict | None:
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
    deadline = time.monotonic() + timeout_s
    run = None
    while time.monotonic() < deadline:
        run = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if run["JobRunState"] in terminal:
            return run
        time.sleep(2)
    return run


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
