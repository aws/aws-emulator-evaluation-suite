"""sdk-glue-job-sqs-message-attributes-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sdk-glue-job-sqs-message-attributes-preserved"
GROUP = "data-format"
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
correlation_id = get_arg('CORRELATION_ID')
job_name = get_arg('JOB_NAME')

sqs = boto3.client('sqs')
sqs.send_message(
    QueueUrl=queue_url,
    MessageBody='job-attrs-test',
    MessageAttributes={
        'JobRunId': {'DataType': 'String', 'StringValue': correlation_id},
        'JobName': {'DataType': 'String', 'StringValue': job_name},
        'RecordCount': {'DataType': 'Number', 'StringValue': '3'},
    },
)
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Custom SQS MessageAttributes set by a Glue job's boto3 send call round-trip intact."""
    queue_url, queue_arn = _create_queue(ctx)
    _, role_arn = _create_glue_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    )
    bucket = _create_glue_bucket(ctx)
    script_location = _upload_script(ctx, bucket, "scripts/attrs.py", _JOB_SCRIPT)
    job_name = _create_pythonshell_job(ctx, role_arn, script_location)

    correlation_id = ctx.unique_name("corr-")
    final = _run_job_until_role_ready(
        ctx, job_name, {"--QUEUE_URL": queue_url, "--CORRELATION_ID": correlation_id, "--JOB_NAME": job_name}
    )
    assert final["JobRunState"] == "SUCCEEDED", final.get("ErrorMessage")

    msg = _receive_one_message(ctx, queue_url, timeout_s=60.0)
    assert msg["Body"] == "job-attrs-test", f"expected body 'job-attrs-test', got {msg['Body']!r}"
    attrs = msg["MessageAttributes"]
    assert attrs["JobRunId"]["StringValue"] == correlation_id, (
        f"expected JobRunId {correlation_id!r}, got {attrs['JobRunId']['StringValue']!r}"
    )
    assert attrs["JobRunId"]["DataType"] == "String", f"expected JobRunId DataType 'String', got {attrs['JobRunId']['DataType']!r}"
    assert attrs["JobName"]["StringValue"] == job_name, (
        f"expected JobName {job_name!r}, got {attrs['JobName']['StringValue']!r}"
    )
    assert attrs["RecordCount"]["DataType"] == "Number", (
        f"expected RecordCount DataType 'Number', got {attrs['RecordCount']['DataType']!r}"
    )
    assert attrs["RecordCount"]["StringValue"] == "3", (
        f"expected RecordCount StringValue '3', got {attrs['RecordCount']['StringValue']!r}"
    )


# ===== helpers =====


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-glue-sqs-"))["QueueUrl"]
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    if ctx.region != "us-east-1":  # S3 rejects an explicit LocationConstraint for us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run_with_retry(ctx, job_name: str, arguments: dict) -> str:
    glue = ctx.client("glue")
    last_err = None
    # IAM role propagation to Glue's assume-role path has no readiness signal, so retry the
    # call that depends on it to a deadline.
    deadline = _capped_deadline(ctx, 60.0)
    while True:
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as err:  # noqa: BLE001 - retry on role-not-yet-assumable
            last_err = err
        if time.monotonic() >= deadline:
            raise last_err
        time.sleep(2)


def _capped_deadline(ctx, seconds: float) -> float:
    """A monotonic deadline `seconds` ahead, capped by the runner's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


_ROLE_NOT_YET_ASSUMABLE = "should be given assume role permissions for Glue Service"


def _run_job_until_role_ready(ctx, job_name: str, arguments: dict, propagation_s: float = 300.0) -> dict:
    """Glue accepts StartJobRun immediately, but the run itself fails with the
    exact message in _ROLE_NOT_YET_ASSUMABLE if IAM role propagation to Glue's
    execution plane has not caught up yet — that failure is observable only by
    running the job, so retry the run itself rather than guessing a wait."""
    deadline = _capped_deadline(ctx, propagation_s)
    while True:
        run_id = _start_job_run_with_retry(ctx, job_name, arguments)
        final = _poll_job_run(ctx, job_name, run_id, timeout_s=90.0, interval_s=10.0)
        if final["JobRunState"] == "SUCCEEDED":
            return final
        if _ROLE_NOT_YET_ASSUMABLE not in (final.get("ErrorMessage") or ""):
            return final
        if time.monotonic() >= deadline:
            return final
        time.sleep(2)


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


def _receive_one_message(ctx, queue_url: str, timeout_s: float) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg
    raise AssertionError(f"no message within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
