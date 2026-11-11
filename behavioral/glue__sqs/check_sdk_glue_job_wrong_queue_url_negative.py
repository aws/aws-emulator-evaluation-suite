"""sdk-glue-job-wrong-queue-url-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sdk-glue-job-wrong-queue-url-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]

GLUE_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_NON_EXISTENT_QUEUE_MESSAGE = "The specified queue does not exist."
# The pinned Glue 3.0 pythonshell runtime ships a boto3 that speaks SQS's query protocol, whose
# NonExistentQueue message differs from the JSON protocol's.
_JOB_NON_EXISTENT_QUEUE_MESSAGE = "The specified queue does not exist for this wsdl version."

_JOB_SCRIPT = """
import sys
import boto3
from botocore.exceptions import ClientError


def get_arg(name):
    key = '--' + name
    if key in sys.argv:
        return sys.argv[sys.argv.index(key) + 1]
    raise SystemExit('missing arg ' + name)


good_queue = get_arg('GOOD_QUEUE_URL')
bad_queue = get_arg('BAD_QUEUE_URL')

sqs = boto3.client('sqs')
sqs.send_message(QueueUrl=good_queue, MessageBody='control-ok')

try:
    sqs.send_message(QueueUrl=bad_queue, MessageBody='should-not-arrive')
    error_code = 'NO_ERROR_RAISED'
    error_message = ''
except ClientError as err:
    error_code = err.response['Error']['Code']
    error_message = err.response['Error'].get('Message', '')

sqs.send_message(QueueUrl=good_queue, MessageBody='error:' + error_code + '|' + error_message)
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job configured with a mistyped/nonexistent SQS queue URL never delivers the
    payload and observes the exact NonExistentQueue error; a real queue in the same run
    (positive control) still receives its message.
    """
    good_queue_url, good_queue_arn = _create_queue(ctx)
    bad_queue_url = good_queue_url.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-nonexistent-")

    # Confirm the bad queue truly does not exist before we rely on that fact.
    sqs = ctx.client("sqs")
    precheck_code, precheck_message = _error(lambda: sqs.get_queue_url(QueueName=bad_queue_url.rsplit("/", 1)[1]))
    assert precheck_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected AWS.SimpleQueueService.NonExistentQueue before the job runs, got {precheck_code!r}"
    )
    assert precheck_message == _NON_EXISTENT_QUEUE_MESSAGE, (
        f"expected {_NON_EXISTENT_QUEUE_MESSAGE!r} before the job runs, got {precheck_message!r}"
    )

    _, role_arn = _create_glue_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]
    )
    bucket = _create_glue_bucket(ctx)
    script_location = _upload_script(ctx, bucket, "scripts/wrong_queue.py", _JOB_SCRIPT)
    job_name = _create_pythonshell_job(ctx, role_arn, script_location)

    final = _run_job_awaiting_role_propagation(
        ctx, job_name, {"--GOOD_QUEUE_URL": good_queue_url, "--BAD_QUEUE_URL": bad_queue_url}
    )
    assert final["JobRunState"] == "SUCCEEDED", final.get("ErrorMessage")

    bodies = _receive_bodies(ctx, good_queue_url, expected_count=2, timeout_s=60.0)
    assert "control-ok" in bodies, f"positive control message never arrived at the good queue: {bodies}"
    error_bodies = [b for b in bodies if b.startswith("error:")]
    assert len(error_bodies) == 1, f"expected exactly 1 error-report message, got {error_bodies} in {bodies}"
    expected_report = f"error:AWS.SimpleQueueService.NonExistentQueue|{_JOB_NON_EXISTENT_QUEUE_MESSAGE}"
    assert error_bodies[0] == expected_report, (
        f"expected the job to observe {expected_report!r}, got {error_bodies[0]!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Return fn()'s ClientError code and message; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-sqs-"), tags={"sim2real": "wrong-queue-url-negative"}
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
        Tags=[{"Key": "sim2real", "Value": "wrong-queue-url-negative"}],
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
    # us-east-1 rejects an explicit LocationConstraint; every other region requires one.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "wrong-queue-url-negative"}]}
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
        Tags={"sim2real": "wrong-queue-url-negative"},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run_with_retry(ctx, job_name: str, arguments: dict) -> str:
    glue = ctx.client("glue")
    last_err = None
    for _ in range(8):
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as err:  # noqa: BLE001 - retry on role-not-yet-assumable
            last_err = err
            time.sleep(5)
    raise last_err  # type: ignore[misc]


_ROLE_PROPAGATION_ERROR = "should be given assume role permissions for Glue Service"


def _run_job_awaiting_role_propagation(
    ctx, job_name: str, arguments: dict, timeout_s: float = 600.0, propagation_deadline_s: float = 120.0
) -> dict:
    """IAM role trust propagation can lag start_job_run's own success: the call returns a
    JobRunId, but the run then fails asynchronously if Glue tries to assume the role before
    the trust policy has propagated. Retry with a fresh run, bounded by propagation_deadline_s,
    until the role is actually assumable or the deadline passes."""
    deadline = time.monotonic() + propagation_deadline_s
    final: dict = {}
    while True:
        run_id = _start_job_run_with_retry(ctx, job_name, arguments)
        final = _poll_job_run(ctx, job_name, run_id, timeout_s=timeout_s, interval_s=10.0)
        if final["JobRunState"] == "SUCCEEDED" or _ROLE_PROPAGATION_ERROR not in (final.get("ErrorMessage") or ""):
            return final
        if time.monotonic() >= deadline:
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
