"""sdk-glue-job-run-writes-batch-messages-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sdk-glue-job-run-writes-batch-messages-to-sqs-positive"
GROUP = "data-format"
SERVICES = ["glue", "sqs"]

GLUE_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_RECORD_COUNT = 5

_JOB_SCRIPT = """
import sys
import json
import boto3


def get_arg(name):
    key = '--' + name
    if key in sys.argv:
        return sys.argv[sys.argv.index(key) + 1]
    raise SystemExit('missing arg ' + name)


queue_url = get_arg('QUEUE_URL')
sqs = boto3.client('sqs')
records = [{'record_id': i, 'value': 'value-' + str(i)} for i in range(5)]
entries = [{'Id': str(r['record_id']), 'MessageBody': json.dumps(r)} for r in records]
resp = sqs.send_message_batch(QueueUrl=queue_url, Entries=entries)
if resp.get('Failed'):
    raise SystemExit('batch send had failures: ' + json.dumps(resp['Failed']))
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job batches records via boto3 send_message_batch; all records land on SQS intact."""
    queue_url, queue_arn = _create_queue(ctx)
    _, role_arn = _create_glue_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    )
    bucket = _create_glue_bucket(ctx)
    script_location = _upload_script(ctx, bucket, "scripts/batch_write.py", _JOB_SCRIPT)
    job_name = _create_pythonshell_job(ctx, role_arn, script_location)

    ctx.client("glue")
    final = _run_job_until_role_propagates(ctx, job_name, {"--QUEUE_URL": queue_url})
    assert final["JobRunState"] == "SUCCEEDED", final.get("ErrorMessage")

    records = _receive_json_bodies(ctx, queue_url, expected_count=_RECORD_COUNT, timeout_s=60.0)
    ids_seen = sorted(r["record_id"] for r in records)
    assert ids_seen == list(range(_RECORD_COUNT)), f"missing/duplicate record ids: {ids_seen}"
    for r in records:
        expected = f"value-{r['record_id']}"
        assert r["value"] == expected, f"record {r['record_id']}: expected value {expected!r}, got {r['value']!r}"


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
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint for its own region
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
    for _ in range(8):
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as err:  # noqa: BLE001 - retry on role-not-yet-assumable
            last_err = err
            time.sleep(5)
    raise last_err  # type: ignore[misc]


def _run_job_until_role_propagates(ctx, job_name: str, arguments: dict, propagation_s: float = 300.0) -> dict:
    """A fresh role can be accepted by start_job_run yet still fail at execution time with
    'should be given assume role permissions for Glue Service' while the trust policy is still
    propagating through IAM; that failure is only visible once the run reaches a terminal state,
    so the run is retried on this specific signature to a deadline."""
    deadline = time.monotonic() + propagation_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        run_id = _start_job_run_with_retry(ctx, job_name, arguments)
        final = _poll_job_run(ctx, job_name, run_id, timeout_s=600.0, interval_s=10.0)
        if final["JobRunState"] == "SUCCEEDED":
            return final
        if "assume role permissions for Glue Service" not in (final.get("ErrorMessage") or ""):
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


def _receive_json_bodies(ctx, queue_url: str, expected_count: int, timeout_s: float) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)}")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
