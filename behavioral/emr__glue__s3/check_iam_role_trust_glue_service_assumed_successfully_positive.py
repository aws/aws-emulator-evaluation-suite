"""iam-role-trust-glue-service-assumed-successfully-positive."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-trust-glue-service-assumed-successfully-positive"
GROUP = "iam-trust"
SERVICES = ["emr", "glue", "s3"]

_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job whose role trusts glue.amazonaws.com is actually assumed and the job runs to
    SUCCEEDED, and the script's own S3 side-effect (a marker object written using the role's own
    credentials) is observed -- proving the role was really assumed, not just accepted as a string."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-glue-trust-"),
        {"Service": "glue.amazonaws.com"},
        managed_policy_arns=[_MANAGED_POLICY],
    )

    marker_key = "markers/good.txt"
    script_key = "scripts/good.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_marker_script(bucket, marker_key).encode())

    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    final = _start_job_run_retrying_iam_propagation(glue, job_name)
    assert final["JobRunState"] == "SUCCEEDED", f"unexpected state: {final}"

    # The observable side effect: the role was actually assumed and used to call S3.
    head = s3.head_object(Bucket=bucket, Key=marker_key)
    assert head["ContentLength"] > 0, f"expected a non-empty marker object, got ContentLength={head.get('ContentLength')}"


def _marker_script(bucket: str, marker_key: str) -> str:
    return (
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        f"s3.put_object(Bucket={bucket!r}, Key={marker_key!r}, Body=b'ok')\n"
        "print('done')\n"
    )


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("aws-glue-sim2real-")
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; every other
    # region requires one naming itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
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
    inline_policies: dict[str, dict] | None = None,
) -> str:
    trust_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}]}
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_doc,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        for arn in managed_policy_arns or []:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pname in (inline_policies or {}):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
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
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _start_job_run_retrying_iam_propagation(
    glue, job_name: str, *, timeout_s: float = 90.0, interval_s: float = 10.0
) -> dict[str, Any]:
    # IAM is eventually consistent globally, and CreateJob/StartJobRun both succeed synchronously
    # even when the role has not propagated -- the failure only surfaces once Glue's own executor
    # tries to assume it, as a FAILED terminal state whose ErrorMessage names the missing
    # propagation ("should be given assume role permissions for Glue Service"). So the retry has to
    # wrap the run itself, not either API call: start a fresh run, wait for a terminal state, and
    # only retry that specific failure -- bounded by a deadline, and any other failure (or the
    # deadline itself) returns immediately for the caller's assertion to judge.
    #
    # A FAILED run's own slot briefly still counts against the job's
    # MaxConcurrentRuns (default 1), so the very next StartJobRun can itself raise
    # ConcurrentRunsExceededException for a few seconds -- that is retried the same way.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            run_id = glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConcurrentRunsExceededException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise
        final = _poll_until(
            lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
            lambda jr: jr["JobRunState"] in _TERMINAL_STATES,
            timeout_s=360,
            interval_s=10,
        )
        if final["JobRunState"] != "FAILED":
            return final
        message = final.get("ErrorMessage") or ""
        if "assume role permissions" in message and time.monotonic() < deadline:
            time.sleep(interval_s)
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
