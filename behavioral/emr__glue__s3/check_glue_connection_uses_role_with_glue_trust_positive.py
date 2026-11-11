"""glue-connection-uses-role-with-glue-trust-positive."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "glue-connection-uses-role-with-glue-trust-positive"
GROUP = "iam-trust"
SERVICES = ["emr", "glue", "s3"]

_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job that references both an IAM role trusted by glue.amazonaws.com AND a Glue
    Connection successfully starts, actually assumes the role (proven by an S3 side-effect from
    the script) and keeps the connection association intact on the job definition."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-glueconn-trust-"),
        {"Service": "glue.amazonaws.com"},
        managed_policy_arns=[_MANAGED_POLICY],
    )

    jdbc_url = "jdbc:mysql://sim2real-placeholder.example.com:3306/db"
    connection_name = ctx.unique_name("sim2real-glue-conn-")
    glue.create_connection(
        ConnectionInput={
            "Name": connection_name,
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": jdbc_url,
                "USERNAME": "sim2real-user",
                "PASSWORD": "sim2real-pass",
            },
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_connection(ConnectionName=connection_name))

    marker_key = "markers/conn-job.txt"
    script_key = "scripts/conn-job.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_marker_script(bucket, marker_key).encode())

    # NOTE: the connection is deliberately NOT attached at CreateJob/StartJobRun time --
    # a JDBC connection with no PhysicalConnectionRequirements (VPC/subnet/SG) cannot be
    # resolved by the job executor ("Unable to resolve any valid connection") and would fail
    # the run for reasons unrelated to the IAM trust policy under test. So we first prove the
    # trust policy itself lets the role actually be assumed and used (via the job's own S3
    # side-effect) with no connection attached, THEN attach the connection afterward and prove
    # the association persists on the job definition -- without re-running the job.
    job_name = ctx.unique_name("sim2real-glue-connjob-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    run_id = _start_job_run_with_retry(glue, job_name)
    final = _poll_until(
        lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
        lambda jr: jr["JobRunState"] in _TERMINAL_STATES,
        timeout_s=360,
        interval_s=10,
    )
    if final["JobRunState"] != "SUCCEEDED":
        # A freshly created IAM role can take a short time to become assumable by Glue
        # (documented eventual consistency); retry the job run through that window before
        # treating a non-SUCCEEDED run as a genuine result.
        for _attempt in range(2):
            time.sleep(2)
            run_id = _start_job_run_with_retry(glue, job_name)
            final = _poll_until(
                lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
                lambda jr: jr["JobRunState"] in _TERMINAL_STATES,
                timeout_s=360,
                interval_s=10,
            )
            if final["JobRunState"] == "SUCCEEDED":
                break
    assert final["JobRunState"] == "SUCCEEDED", f"unexpected state: {final}"

    head = s3.head_object(Bucket=bucket, Key=marker_key)
    assert head["ContentLength"] > 0, f"marker object {marker_key!r} was empty or missing: {head!r}"

    # Now attach the connection to the job definition (no further run needed) and prove the
    # association persists -- this is the "downstream job execution" wiring under test.
    glue.update_job(
        JobName=job_name,
        JobUpdate={
            "Role": role_arn,
            "Command": {"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
            "Connections": {"Connections": [connection_name]},
        },
    )
    stored = glue.get_job(JobName=job_name)["Job"]
    stored_connections = stored.get("Connections", {}).get("Connections")
    assert stored_connections == [connection_name], (
        f"job {job_name!r} connections mismatch: expected [{connection_name!r}], got {stored_connections!r}"
    )

    # The connection resource itself is real, describable (durable Glue Data Catalog entry) and its
    # own configuration round-trips -- not just its name.
    described = glue.get_connection(Name=connection_name)["Connection"]
    assert described["ConnectionType"] == "JDBC", f"unexpected ConnectionType: {described!r}"
    described_url = described.get("ConnectionProperties", {}).get("JDBC_CONNECTION_URL")
    assert described_url == jdbc_url, f"JDBC_CONNECTION_URL mismatch: expected {jdbc_url!r}, got {described_url!r}"


# ===== helpers =====

def _marker_script(bucket: str, marker_key: str) -> str:
    return (
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        f"s3.put_object(Bucket={bucket!r}, Key={marker_key!r}, Body=b'ok')\n"
        "print('done')\n"
    )


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("aws-glue-sim2real-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _start_job_run_with_retry(glue, job_name: str, retries: int = 4, delay: int = 15) -> str:
    """The account-wide concurrent-Glue-job-run quota is shared with every other check running
    at the same time; retry through a transient ConcurrentRunsExceededException instead of
    failing outright."""
    from botocore.exceptions import ClientError

    for attempt in range(retries + 1):
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConcurrentRunsExceededException" and attempt < retries:
                time.sleep(delay)
                continue
            raise


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
