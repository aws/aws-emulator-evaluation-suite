"""cli-glue-job-run-status-poll-sqs-completion-positive."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-glue-job-run-status-poll-sqs-completion-positive"
GROUP = "cli-workflow"
SERVICES = ["glue", "sqs"]

GLUE_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"

# The script sleeps before publishing so a CLI poller has a comfortable window
# to observe RUNNING.
_JOB_SCRIPT = """
import sys
import time
import boto3


def get_arg(name):
    key = '--' + name
    if key in sys.argv:
        return sys.argv[sys.argv.index(key) + 1]
    raise SystemExit('missing arg ' + name)


queue_url = get_arg('QUEUE_URL')
run_tag = get_arg('RUN_TAG')

time.sleep(25)

sqs = boto3.client('sqs')
sqs.send_message(QueueUrl=queue_url, MessageBody='completed:' + run_tag)
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job run polled through the CLI is seen RUNNING and then SUCCEEDED, and the completion
    message the job sends reaches the SQS queue with this run's exact body.
    """
    require_tools("aws")

    queue_url, queue_arn = _create_queue(ctx)
    _, role_arn = _create_glue_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    )
    bucket = _create_glue_bucket(ctx)
    script_location = _upload_script(ctx, bucket, "scripts/delayed_notify.py", _JOB_SCRIPT)
    job_name = _create_pythonshell_job(ctx, role_arn, script_location)

    run_tag = ctx.unique_name("run-tag-")
    env = ctx.subprocess_env()
    state, error_message, observed_running = _run_job_absorbing_role_propagation(
        env, job_name, queue_url, run_tag
    )

    assert observed_running, "never observed the job in RUNNING state"
    assert state == "SUCCEEDED", f"job run ended in {state}: {error_message}"

    body = _receive_one_body(ctx, queue_url, timeout_s=60.0)
    assert body == f"completed:{run_tag}", f"expected completed:{run_tag}, got {body!r}"


def _run_aws_json(env: dict, args: list[str]) -> Any:
    proc = subprocess.run(
        ["aws", *args, "--output", "json"], capture_output=True, env=env, timeout=60, text=True
    )
    if proc.returncode != 0:
        raise AssertionError(f"aws {' '.join(args)} failed: {proc.stderr}")
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
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


_ROLE_NOT_YET_ASSUMABLE = "should be given assume role permissions"
_CONCURRENT_RUNS_EXCEEDED = "ConcurrentRunsExceededException"


def _start_job_run(env: dict, job_name: str, run_tag: str, queue_url: str, timeout_s: float = 30.0) -> Any:
    """A job just marked FAILED can still hold its concurrency slot for a moment: retries past
    ConcurrentRunsExceededException, which is Glue's own transient release lag rather than a
    real over-limit condition (this job's MaxConcurrentRuns default is 1 and nothing else targets it)."""
    args = [
        "glue",
        "start-job-run",
        "--job-name",
        job_name,
        "--arguments",
        json.dumps({"--QUEUE_URL": queue_url, "--RUN_TAG": run_tag}),
    ]
    deadline = time.monotonic() + timeout_s
    while True:
        proc = subprocess.run(
            ["aws", *args, "--output", "json"], capture_output=True, env=env, timeout=60, text=True
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        if _CONCURRENT_RUNS_EXCEEDED in proc.stderr and time.monotonic() < deadline:
            time.sleep(3)
            continue
        raise AssertionError(f"aws {' '.join(args)} failed: {proc.stderr}")


def _run_job_absorbing_role_propagation(
    env: dict, job_name: str, queue_url: str, run_tag: str, propagation_timeout_s: float = 90.0
) -> tuple[str, str | None, bool]:
    """Runs the job to a terminal state, retrying the whole run (not just the start-job-run call,
    which is accepted before Glue ever checks the role) while the failure is specifically the
    freshly created role not yet being assumable -- IAM trust-policy propagation lands after
    create_role returns, and Glue only discovers that when it tries to assume the role at
    execution time, well after start-job-run has already returned success."""
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"}
    propagation_deadline = time.monotonic() + propagation_timeout_s
    while True:
        start_out = _start_job_run(env, job_name, run_tag, queue_url)
        run_id = start_out["JobRunId"]

        observed_running = False
        state = "STARTING"
        error_message = None
        poll_deadline = time.monotonic() + 600.0
        while time.monotonic() < poll_deadline:
            out = _run_aws_json(env, ["glue", "get-job-run", "--job-name", job_name, "--run-id", run_id])
            job_run = out["JobRun"]
            state = job_run["JobRunState"]
            if state == "RUNNING":
                observed_running = True
            if state in terminal:
                error_message = job_run.get("ErrorMessage")
                break
            time.sleep(4)

        is_propagation_failure = (
            state == "FAILED" and error_message is not None and _ROLE_NOT_YET_ASSUMABLE in error_message
        )
        if is_propagation_failure and time.monotonic() < propagation_deadline:
            time.sleep(5)
            continue
        return state, error_message, observed_running


def _receive_one_body(ctx, queue_url: str, timeout_s: float) -> str:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    raise AssertionError(f"no completion message within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
