"""cli-start-glue-job-run-sqs-notification-positive."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-start-glue-job-run-sqs-notification-positive"
GROUP = "cli-workflow"
SERVICES = ["glue", "sqs"]

GLUE_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"

_JOB_SCRIPT = """
import sys
import boto3


def get_arg(name):
    key = '--' + name
    if key in sys.argv:
        return sys.argv[sys.argv.index(key) + 1]
    raise SystemExit('missing arg ' + name)


queue_url = get_arg('QUEUE_URL')
job_name = get_arg('JOB_NAME')

sqs = boto3.client('sqs')
sqs.send_message(QueueUrl=queue_url, MessageBody='job-complete:' + job_name)
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws glue start-job-run` + CLI polling drives a job that notifies completion via SQS."""
    require_tools("aws")

    queue_url, queue_arn = _create_queue(ctx)
    role_name, role_arn = _create_glue_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    )
    bucket = _create_glue_bucket(ctx)
    script_location = _upload_script(ctx, bucket, "scripts/notify.py", _JOB_SCRIPT)
    job_name = _create_pythonshell_job(ctx, role_arn, script_location)

    env = ctx.subprocess_env()
    final_state, error_message = _start_job_run_and_await_terminal(
        env, job_name, queue_url, propagation_deadline_s=90.0
    )
    assert final_state == "SUCCEEDED", f"job run ended in {final_state}: {error_message}"

    messages = _receive_bodies(ctx, queue_url, expected_count=1, timeout_s=60.0)
    expected = [f"job-complete:{job_name}"]
    assert messages == expected, f"expected {expected!r}, got {messages!r}"


def _run_aws(env: dict, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["aws", *args, "--output", "json"], capture_output=True, env=env, timeout=60, text=True
    )


def _run_aws_json(env: dict, args: list[str]) -> Any:
    proc = _run_aws(env, args)
    if proc.returncode != 0:
        raise AssertionError(f"aws {' '.join(args)} failed: {proc.stderr}")
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


_ROLE_PROPAGATION_MARKER = "should be given assume role permissions"
_CONCURRENT_RUNS_MARKER = "ConcurrentRunsExceededException"


def _start_job_run_and_await_terminal(
    env: dict, job_name: str, queue_url: str, propagation_deadline_s: float
) -> tuple[str, str]:
    """`start-job-run` itself always succeeds against a freshly created role: Glue only
    tries (and can fail) to assume the role once the run actually executes, surfacing as a
    FAILED terminal state with this specific InvalidInputException, confirmed on real AWS.
    A retried start can also briefly race the previous run's own FAILED transition,
    surfacing as ConcurrentRunsExceededException, also confirmed on real AWS. Retry the
    whole start+await cycle while either specific signature persists, bounded by
    `propagation_deadline_s`; any other terminal state or message fails immediately."""
    deadline = time.monotonic() + propagation_deadline_s
    while True:
        start_args = [
            "glue",
            "start-job-run",
            "--job-name",
            job_name,
            "--arguments",
            json.dumps({"--QUEUE_URL": queue_url, "--JOB_NAME": job_name}),
        ]
        proc = _run_aws(env, start_args)
        if proc.returncode != 0:
            if _CONCURRENT_RUNS_MARKER in proc.stderr and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise AssertionError(f"aws {' '.join(start_args)} failed: {proc.stderr}")
        run_id = json.loads(proc.stdout)["JobRunId"]
        state, error_message = _poll_job_run_cli(env, job_name, run_id, timeout_s=600.0, interval_s=10.0)
        if state == "SUCCEEDED" or _ROLE_PROPAGATION_MARKER not in error_message:
            return state, error_message
        if time.monotonic() >= deadline:
            return state, error_message
        time.sleep(5.0)


def _poll_job_run_cli(env: dict, job_name: str, run_id: str, timeout_s: float, interval_s: float) -> tuple[str, str]:
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"}
    deadline = time.monotonic() + timeout_s
    state = "STARTING"
    error_message = ""
    while time.monotonic() < deadline:
        out = _run_aws_json(env, ["glue", "get-job-run", "--job-name", job_name, "--run-id", run_id])
        job_run = out["JobRun"]
        state = job_run["JobRunState"]
        if state in terminal:
            return state, job_run.get("ErrorMessage", "")
        time.sleep(interval_s)
    raise AssertionError(f"job run stuck in {state} after {timeout_s}s")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-sqs-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_glue_role(ctx, inline_statements=None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=GLUE_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=GLUE_MANAGED_POLICY_ARN))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-glue-inline-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _create_glue_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("aws-glue-sim2real-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _upload_script(ctx, bucket: str, key: str, body: str) -> str:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
    return f"s3://{bucket}/{key}"


def _create_pythonshell_job(ctx, role_arn: str, script_location: str) -> str:
    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "ScriptLocation": script_location, "PythonVersion": "3.9"},
        GlueVersion="3.0",
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _receive_bodies(ctx, queue_url: str, expected_count: int, timeout_s: float) -> list[str]:
    sqs = ctx.client("sqs")
    out: list[str] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)}")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
