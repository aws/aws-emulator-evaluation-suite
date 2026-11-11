"""glue-job-start-with-role-missing-glue-trust-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "glue-job-start-with-role-missing-glue-trust-rejected"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]

_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job whose role trusts ec2.amazonaws.com rather than glue.amazonaws.com ends FAILED with an
    ErrorMessage and writes nothing to S3, while an identical job whose role trusts glue.amazonaws.com
    succeeds and writes its object."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx, s3)

    good_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-goodtrust-"),
        {"Service": "glue.amazonaws.com"},
        managed_policy_arns=[_MANAGED_POLICY],
    )
    bad_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-badtrust-"),
        {"Service": "ec2.amazonaws.com"},  # only the trust principal differs from the good role
        managed_policy_arns=[_MANAGED_POLICY],
    )

    good_job = _make_job(ctx, glue, s3, bucket, good_role_arn, "good")
    bad_job = _make_job(ctx, glue, s3, bucket, bad_role_arn, "bad")

    good_final = _run_job_to_terminal(glue, good_job["name"])
    bad_final = _run_job_to_terminal(glue, bad_job["name"])

    # Positive control: the correctly-trusted role succeeds and its side-effect is observed.
    assert good_final["JobRunState"] == "SUCCEEDED", f"positive control failed: {good_final}"
    head = s3.head_object(Bucket=bucket, Key=good_job["marker_key"])
    assert head["ContentLength"] > 0

    # Negative: the mistrusted role's run fails, and its side-effect never happened.
    assert bad_final["JobRunState"] == "FAILED", f"expected FAILED, got: {bad_final}"
    assert bad_final.get("ErrorMessage"), "FAILED job run should carry a non-empty ErrorMessage"
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=bad_job["marker_key"]))
    assert code == "404", "the mistrusted role's script must never have run (marker absent)"


def _make_job(ctx, glue, s3, bucket: str, role_arn: str, label: str) -> dict[str, str]:
    marker_key = f"markers/{label}.txt"
    script_key = f"scripts/{label}.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_marker_script(bucket, marker_key).encode())
    job_name = ctx.unique_name(f"sim2real-glue-{label}job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return {"name": job_name, "marker_key": marker_key}


def _marker_script(bucket: str, marker_key: str) -> str:
    return (
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        f"s3.put_object(Bucket={bucket!r}, Key={marker_key!r}, Body=b'ok')\n"
        "print('done')\n"
    )


def _error_code(fn: Callable[[], Any]) -> str:
    """The ClientError code `fn` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError("the call succeeded where an error was expected")


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("aws-glue-sim2real-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    objs = resp.get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_role(
    ctx,
    iam,
    role_name: str,
    trust_principal: dict[str, Any],
    managed_policy_arns: list[str] | None = None,
) -> str:
    trust_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}]}
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_doc,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        for arn in managed_policy_arns or []:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    return role_arn


_IAM_PROPAGATION_WINDOW_S = 20.0  # AWS's documented eventual-consistency ceiling for IAM
# https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency


def _run_job_to_terminal(glue, job_name: str, *, timeout_s: float = 4 * _IAM_PROPAGATION_WINDOW_S) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports a role Glue cannot assume as a FAILED job *run* a few seconds in, not as a
    StartJobRun error -- and that FAILED message is identical whether the trust principal merely
    has not propagated yet or is permanently wrong (no API reports that a role has become
    assumable). So absence of success is bounded by a calibrated window, not a blind sleep before
    the first attempt: retry across ~4x IAM's documented propagation ceiling. A freshly-trusted
    role clears within that window; a role trusting the wrong principal keeps failing with the
    same message until the deadline, which is exactly the FAILED result the negative expects.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    record: dict = {}
    while time.monotonic() < deadline:
        try:
            run_id = glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < deadline:
            record = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
            if record["JobRunState"] in _TERMINAL_STATES:
                break
            time.sleep(5)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role" not in (record.get("ErrorMessage") or "").lower():
            return record
        time.sleep(5)
    return record


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
