"""sdk-glue-job-missing-sqs-send-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sdk-glue-job-missing-sqs-send-permission-negative"
GROUP = "overly-permissive"
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
tag = get_arg('TAG')
sqs = boto3.client('sqs')
sqs.send_message(QueueUrl=queue_url, MessageBody='permitted:' + tag)
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job run whose role lacks sqs:SendMessage ends FAILED with AccessDenied and delivers
    nothing, a permitted role's run SUCCEEDS and delivers, and after the grant the same
    StartJobRun delivers too.
    """
    queue_url, queue_arn = _create_queue(ctx)
    bucket = _create_glue_bucket(ctx)
    script_location = _upload_script(ctx, bucket, "scripts/permission_probe.py", _JOB_SCRIPT)

    _, allowed_role_arn = _create_glue_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    )
    denied_role_name, denied_role_arn = _create_glue_role(ctx)  # no sqs permission at all

    allowed_job = _create_pythonshell_job(ctx, allowed_role_arn, script_location)
    denied_job = _create_pythonshell_job(ctx, denied_role_arn, script_location)

    # Positive control: the permitted role's run succeeds and its message is delivered.
    allowed_tag = ctx.unique_name("allowed-")
    allowed_final = _run_job_with_role_ready_retry(
        ctx, allowed_job, {"--QUEUE_URL": queue_url, "--TAG": allowed_tag}
    )
    assert allowed_final["JobRunState"] == "SUCCEEDED", (
        f"positive control expected SUCCEEDED, got {allowed_final['JobRunState']!r}: "
        f"{allowed_final.get('ErrorMessage')!r}"
    )
    body = _receive_one_body(ctx, queue_url, timeout_s=60.0)
    assert body == f"permitted:{allowed_tag}", f"expected 'permitted:{allowed_tag}', got {body!r}"

    # Negative: the role without sqs:SendMessage fails the run and delivers nothing.
    denied_tag = ctx.unique_name("denied-")
    denied_final = _run_job_with_role_ready_retry(
        ctx, denied_job, {"--QUEUE_URL": queue_url, "--TAG": denied_tag}
    )
    assert denied_final["JobRunState"] == "FAILED", (
        f"expected FAILED for a role lacking sqs:SendMessage, got {denied_final['JobRunState']!r}"
    )
    denied_error = denied_final.get("ErrorMessage") or ""
    assert "AccessDenied" in denied_error, f"expected AccessDenied in ErrorMessage, got {denied_error!r}"
    leftover = ctx.client("sqs").receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in leftover.get("Messages", []):
        assert not msg["Body"].startswith(f"permitted:{denied_tag}"), (
            f"message {msg['Body']!r} should never have been delivered by the denied role"
        )

    # Restore: grant the SAME role the missing permission, then the identical StartJobRun call
    # (same job) now succeeds and its message really arrives. A freshly-granted inline policy can
    # lag briefly before Glue's execution sees it, so retry the identical call on that specific
    # symptom (AccessDenied) rather than trusting a fixed sleep -- never on any other failure.
    _grant_sqs_send(ctx, denied_role_name, queue_arn)
    restore_deadline = time.monotonic() + 180.0
    attempt = 0
    while True:
        attempt += 1
        restored_tag = ctx.unique_name(f"restored-{attempt}-")
        restored_final = _run_job_with_role_ready_retry(
            ctx, denied_job, {"--QUEUE_URL": queue_url, "--TAG": restored_tag}
        )
        if restored_final["JobRunState"] == "SUCCEEDED":
            break
        restored_error = restored_final.get("ErrorMessage") or ""
        if "AccessDenied" not in restored_error or time.monotonic() >= restore_deadline:
            raise AssertionError(
                f"after granting sqs:SendMessage, expected SUCCEEDED, got "
                f"{restored_final['JobRunState']!r}: {restored_error!r}"
            )
        time.sleep(5)
    restored_body = _receive_one_body(ctx, queue_url, timeout_s=60.0)
    assert restored_body == f"permitted:{restored_tag}", (
        f"expected 'permitted:{restored_tag}' after restoring the permission, got {restored_body!r}"
    )


_MANAGED_TAG = {"sim2real:managed": "true"}


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-glue-sqs-"), tags=_MANAGED_TAG)["QueueUrl"]
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
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAG.items()],
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
    # No fixed sleep for IAM/Glue propagation here: _start_job_run_with_retry bounds that wait
    # against the real StartJobRun call below, on the specific symptom, with a stated deadline.
    return role_name, role_arn


def _grant_sqs_send(ctx, role_name: str, queue_arn: str) -> None:
    """Restore beat: give an already-created role the permission it was missing."""
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-glue-inline-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_glue_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("aws-glue-sim2real-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MANAGED_TAG.items()]}
    )
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
        Tags=dict(_MANAGED_TAG),
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run_with_retry(ctx, job_name: str, arguments: dict) -> str:
    """Bounded retry (8 attempts, 5s apart, ~40s deadline) on StartJobRun itself -- this is what
    absorbs IAM role/policy propagation lag for a just-created or just-modified role, instead of a
    fixed sleep before the call."""
    glue = ctx.client("glue")
    last_err = None
    for _ in range(8):
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as err:  # noqa: BLE001 - retry on role-not-yet-assumable
            last_err = err
            time.sleep(5)
    raise last_err  # type: ignore[misc]


_ROLE_NOT_READY_MARKERS = (
    "should be given assume role permissions",
    "is not authorized to perform: sts:assumerole",
)


def _run_job_with_role_ready_retry(
    ctx, job_name: str, arguments: dict, *, role_ready_timeout_s: float = 180.0
) -> dict:
    """Start and poll a job run. If it fails ONLY because Glue could not yet assume a
    just-created/just-modified role (IAM trust propagation lag), retry a
    fresh run of the same job -- bounded by role_ready_timeout_s -- instead of trusting a fixed
    sleep before the first attempt. Any other terminal state, including the AccessDenied this check
    exists to detect, is returned immediately, unretried."""
    deadline = time.monotonic() + role_ready_timeout_s
    while True:
        run_id = _start_job_run_with_retry(ctx, job_name, arguments)
        final = _poll_job_run(ctx, job_name, run_id, timeout_s=600.0, interval_s=10.0)
        if final["JobRunState"] != "FAILED":
            return final
        error = (final.get("ErrorMessage") or "").lower()
        if not any(marker in error for marker in _ROLE_NOT_READY_MARKERS) or time.monotonic() >= deadline:
            return final
        time.sleep(5)


def _poll_job_run(ctx, job_name: str, run_id: str, timeout_s: float, interval_s: float) -> dict:
    glue = ctx.client("glue")
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"}
    deadline = time.monotonic() + timeout_s
    resp: dict = {}
    while time.monotonic() < deadline:
        resp = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if resp["JobRunState"] in terminal:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"job run did not reach terminal state within {timeout_s}s: {resp}")


def _receive_one_body(ctx, queue_url: str, timeout_s: float) -> str:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    raise AssertionError(f"no message within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
