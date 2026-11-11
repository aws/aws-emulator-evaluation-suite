"""iam-role-missing-glue-trust-assume-role-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-missing-glue-trust-assume-role-negative"
GROUP = "overly-permissive"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job whose role does not trust glue.amazonaws.com is created but its run ends FAILED with an
    assume-role error and writes no marker, while the same job with a glue-trusting role SUCCEEDS
    and writes it.
    """
    ctx.client("iam")
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_aws_glue_bucket(ctx)
    script_key = "script.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT.encode())

    # --- Untrusted role: trusts sqs.amazonaws.com, NOT glue.amazonaws.com ---
    bad_role_name = ctx.unique_name("sim2real-glue-badtrust-")
    bad_role_arn = _create_role(
        ctx,
        bad_role_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "sqs.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
    )
    _attach_glue_service_policy(ctx, bad_role_name)

    bad_job_name = ctx.unique_name("sim2real-glue-badjob-")
    glue.create_job(
        Name=bad_job_name,
        Role=bad_role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=bad_job_name))

    bad_marker_key = "bad-marker.txt"
    bad_run_id = _start_job_run_with_retry(
        glue, bad_job_name, {"--marker_bucket": bucket, "--marker_key": bad_marker_key, "--region": ctx.region}
    )
    bad_final = _poll_job_run_terminal(glue, bad_job_name, bad_run_id, timeout_s=90)
    assert bad_final["JobRunState"] == "FAILED", (
        f"expected job run with an untrusted role to fail, got {bad_final.get('JobRunState')}"
    )
    bad_error = bad_final.get("ErrorMessage") or ""
    assert "assum" in bad_error.lower() or "not authorized" in bad_error.lower() or "sts:assumerole" in bad_error.lower(), (
        f"expected the failure to name the assume-role rejection, got ErrorMessage={bad_error!r}"
    )
    assert _object_missing(s3, bucket, bad_marker_key), "script side effect happened despite untrusted role"

    # --- Positive control: role trusts glue.amazonaws.com, same everything else ---
    good_role_name = ctx.unique_name("sim2real-glue-goodtrust-")
    good_role_arn = _create_role(
        ctx,
        good_role_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
    )
    _attach_glue_service_policy(ctx, good_role_name)

    good_job_name = ctx.unique_name("sim2real-glue-goodjob-")
    glue.create_job(
        Name=good_job_name,
        Role=good_role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=good_job_name))

    good_marker_key = "good-marker.txt"
    good_final = _run_job_past_trust_propagation(
        glue, good_job_name, {"--marker_bucket": bucket, "--marker_key": good_marker_key, "--region": ctx.region}
    )
    assert good_final["JobRunState"] == "SUCCEEDED", (
        f"positive control job run failed: {good_final.get('ErrorMessage')}"
    )
    s3.head_object(Bucket=bucket, Key=good_marker_key)


def _create_role(ctx: Any, role_name: str, trust_doc: dict) -> str:
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _start_job_run_with_retry(glue, job_name: str, arguments: dict, timeout_s: float = 90.0, interval_s: float = 10.0) -> str:
    """StartJobRun can fail immediately right after CreateRole/CreateJob while
    IAM role visibility is still propagating to the Glue control plane; retry
    the call itself on a bounded deadline rather than sleeping blind."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"start_job_run kept failing (IAM propagation never settled): {last_err}")


def _run_job_past_trust_propagation(glue, job_name: str, arguments: dict, run_timeout_s: float = 60.0) -> dict:
    """A just-created role that DOES trust glue.amazonaws.com can still fail its first job run with
    the exact same 'should be given assume role permissions' error a permanently-untrusted role gets,
    purely because IAM has not finished propagating the trust change to the Glue control plane. Retry
    the whole run (not just the StartJobRun call) on that specific symptom, on a bounded deadline."""
    backoffs = (15.0, 30.0)
    last: dict = {}
    for attempt in range(len(backoffs) + 1):
        run_id = _start_job_run_with_retry(glue, job_name, arguments)
        last = _poll_job_run_terminal(glue, job_name, run_id, timeout_s=run_timeout_s)
        if last["JobRunState"] == "SUCCEEDED":
            return last
        if "assume role permissions" not in (last.get("ErrorMessage") or "").lower():
            return last
        if attempt < len(backoffs):
            time.sleep(backoffs[attempt])
    return last


def _attach_glue_service_policy(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))


def _create_aws_glue_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("aws-glue-sim2real-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _object_missing(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        return code in ("404", "NoSuchKey", "NotFound")
    return False


def _poll_job_run_terminal(glue, job_name: str, run_id: str, timeout_s: float = 300.0) -> dict:
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
