"""glue-job-role-missing-trust-policy-negative."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-job-role-missing-trust-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]

_GOOD_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
# Same shape, wrong principal: this role has correct S3/Glue permissions but Glue
# itself can never assume it, because its trust policy does not name glue.amazonaws.com.
_BAD_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
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
s3.put_object(Bucket=args["dst_bucket"], Key=args["dst_key"], Body=body.upper())
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job whose role does not trust glue.amazonaws.com ends FAILED and writes no output, while
    an identical job with a role that trusts it succeeds."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-jobtrust-")
    _create_bucket(ctx, s3, bucket)
    script_key = "scripts/job.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT.encode("utf-8"))
    src_key = "input/source.txt"
    src_body = b"trust-policy boundary test payload"
    s3.put_object(Bucket=bucket, Key=src_key, Body=src_body)
    dst_key = "output/result.txt"

    bad_role_arn, bad_role_name = _make_role(ctx, iam, "bad", _BAD_TRUST, bucket)
    good_role_arn, good_role_name = _make_role(ctx, iam, "good", _GOOD_TRUST, bucket)

    job_name = ctx.unique_name("sim2real-jobtrust-")
    glue.create_job(
        Name=job_name,
        Role=bad_role_arn,
        Command={"Name": "pythonshell", "ScriptLocation": f"s3://{bucket}/{script_key}", "PythonVersion": "3.9"},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    bad_run_id = _start_job_run_with_retry(
        glue, job_name,
        {"--src_bucket": bucket, "--src_key": src_key, "--dst_bucket": bucket, "--dst_key": dst_key},
    )
    bad_state = _wait_for_job_run(glue, job_name, bad_run_id, timeout_s=240)

    assert bad_state == "FAILED", f"job with mistrusted role ended as {bad_state!r}, expected FAILED"
    assert _object_absent(s3, bucket, dst_key), "output object should not exist after a mistrusted-role job run"

    # Positive control in the same file: swap in a role with correct trust, everything else equal.
    glue.update_job(
        JobName=job_name,
        JobUpdate={
            "Role": good_role_arn,
            "Command": {
                "Name": "pythonshell",
                "ScriptLocation": f"s3://{bucket}/{script_key}",
                "PythonVersion": "3.9",
            },
        },
    )
    good_state, good_run_id = _start_and_wait_with_retry(
        glue, job_name,
        {"--src_bucket": bucket, "--src_key": src_key, "--dst_bucket": bucket, "--dst_key": dst_key},
        timeout_s=240,
    )

    assert good_state == "SUCCEEDED", f"control job with correctly-trusted role ended as {good_state!r}"
    result = s3.get_object(Bucket=bucket, Key=dst_key)["Body"].read()
    assert result == src_body.upper(), f"destination object body {result!r} != expected {src_body.upper()!r}"


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _make_role(ctx, iam, label: str, trust_doc: dict, bucket: str):
    role_name = ctx.unique_name(f"sim2real-jobtrust-{label}-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="rw-bucket", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="rw-bucket"))
    return role_arn, role_name


def _wait_for_job_run(glue, job_name: str, run_id: str, timeout_s: int = 240) -> str | None:
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]["JobRunState"]
        if state in terminal:
            return state
        time.sleep(2)
    return state


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


def _start_and_wait_with_retry(glue, job_name: str, arguments: dict, timeout_s: int = 240, retries: int = 2, delay: int = 15):
    """A newly (re)assigned execution role can take a short time to become
    assumable by Glue; retry the job run through that documented eventual-
    consistency window before treating a FAILED run as a genuine result."""
    state = None
    run_id = None
    for attempt in range(retries + 1):
        run_id = _start_job_run_with_retry(glue, job_name, arguments)
        state = _wait_for_job_run(glue, job_name, run_id, timeout_s=timeout_s)
        if state == "SUCCEEDED" or attempt == retries:
            return state, run_id
        time.sleep(delay)
    return state, run_id


def _object_absent(s3, bucket: str, key: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        s3.head_object(Bucket=bucket, Key=key)
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] == "404"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
