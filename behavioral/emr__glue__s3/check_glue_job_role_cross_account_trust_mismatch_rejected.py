"""glue-job-role-cross-account-trust-mismatch-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "glue-job-role-cross-account-trust-mismatch-rejected"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]

_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
# Glue's wording when it cannot assume the role: "...should be given assume role permissions for
# Glue Service."
_ASSUME_ROLE_FAILURE_RE = re.compile(r"assume\s*role|not authorized|access.?denied", re.IGNORECASE)



@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job whose role trusts the account root rather than glue.amazonaws.com ends FAILED with an
    assume-role error and writes nothing to S3, while an identical job whose role trusts
    glue.amazonaws.com succeeds and writes its object."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    unrelated_principal = {"AWS": f"arn:aws:iam::{account_id}:root"}

    bucket = _create_bucket(ctx, s3)

    good_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-xacctgood-"),
        {"Service": "glue.amazonaws.com"},
        managed_policy_arns=[_MANAGED_POLICY],
    )
    bad_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-xacctbad-"),
        unrelated_principal,  # account-root principal, not glue.amazonaws.com at all
        managed_policy_arns=[_MANAGED_POLICY],
    )

    good_job = _make_job(ctx, glue, s3, bucket, good_role_arn, "xacctgood")
    bad_job = _make_job(ctx, glue, s3, bucket, bad_role_arn, "xacctbad")

    # The trust policy just attached to good_role_arn is eventually consistent from
    # Glue's STS caller, so a run started immediately can transiently fail the same
    # way a genuine trust mismatch would. Retry the positive control itself -- a fresh
    # job run, not a fixed wait -- while the failure names AssumeRole/authorization;
    # any other failure shape is a real defect and is not retried.
    good_final = _run_until_terminal_with_propagation_retry(glue, good_job, deadline_s=90)
    bad_final = _run_until_terminal(glue, bad_job)

    # Positive control: the glue-trusted role succeeds and its side-effect is observed.
    assert good_final["JobRunState"] == "SUCCEEDED", f"positive control failed: {good_final}"
    head = s3.head_object(Bucket=bucket, Key=good_job["marker_key"])
    assert head["ContentLength"] > 0

    # Negative: the cross-account-trusted role's run fails, and its side-effect never happened.
    assert bad_final["JobRunState"] == "FAILED", f"expected FAILED, got: {bad_final}"
    error_message = bad_final.get("ErrorMessage") or ""
    assert error_message, "FAILED job run should carry a non-empty ErrorMessage"
    assert _ASSUME_ROLE_FAILURE_RE.search(error_message), (
        f"expected the failure to name the assume-role/authorization rejection, got: {error_message!r}"
    )
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=bad_job["marker_key"]))
    assert code == "404", "the cross-account-trusted role's script must never have run (marker absent)"


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
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 --
        # the literal names that one region's API quirk, not a pinned deployment target.
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


def _run_until_terminal(glue, job: dict[str, str]) -> dict[str, Any]:
    run_id = glue.start_job_run(JobName=job["name"])["JobRunId"]
    return _poll_until(
        lambda: glue.get_job_run(JobName=job["name"], RunId=run_id)["JobRun"],
        lambda jr: jr["JobRunState"] in _TERMINAL_STATES,
        timeout_s=360,
        interval_s=10,
    )


def _run_until_terminal_with_propagation_retry(glue, job: dict[str, str], deadline_s: float) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            final = _run_until_terminal(glue, job)
        except ClientError as exc:
            # A run that just failed on the assume-role race hasn't released Glue's
            # per-job concurrency slot yet; back off before the next StartJobRun.
            if exc.response["Error"]["Code"] == "ConcurrentRunsExceededException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
        if final["JobRunState"] == "SUCCEEDED":
            return final
        err = final.get("ErrorMessage") or ""
        if _ASSUME_ROLE_FAILURE_RE.search(err) and time.monotonic() < deadline:
            time.sleep(5)
            continue
        return final


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
