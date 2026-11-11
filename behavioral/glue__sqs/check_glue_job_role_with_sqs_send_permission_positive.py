"""glue-job-role-with-sqs-send-permission-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "glue-job-role-with-sqs-send-permission-positive"
GROUP = "permission-boundary"
SERVICES = ["glue", "sqs"]

_SCRIPT = """
import sys
import boto3


def _arg(flag):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


queue_url = _arg("--queue_url")
region = _arg("--region")
sqs = boto3.client("sqs", region_name=region)
sqs.send_message(QueueUrl=queue_url, MessageBody="glue-job-complete")
print("message sent")
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Python shell Glue job whose role has sqs:SendMessage SUCCEEDS and its "glue-job-complete"
    message arrives on the SQS queue.
    """
    glue = ctx.client("glue")
    sqs = ctx.client("sqs")
    s3 = ctx.client("s3")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-glue-notify-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    role_arn, role_name = _create_glue_role_with_sqs_send(ctx, queue_arn)
    bucket = _create_aws_glue_bucket(ctx)
    script_key = "notify.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT.encode())

    job_name = ctx.unique_name("sim2real-glue-notify-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    final = _run_job_until_role_propagates(
        glue, job_name, arguments={"--queue_url": queue_url, "--region": ctx.region}
    )
    assert final["JobRunState"] == "SUCCEEDED", (
        f"job run failed: {final.get('JobRunState')} / {final.get('ErrorMessage')}"
    )

    body = _wait_for_message_body(sqs, queue_url, timeout_s=30)
    assert body == "glue-job-complete", f"unexpected/absent completion message: {body!r}"


def _create_glue_role_with_sqs_send(ctx: Any, queue_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-sqs-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc))["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    send_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sqs-send", PolicyDocument=json.dumps(send_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))
    return role_arn, role_name


def _create_aws_glue_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("aws-glue-sim2real-")
    # "us-east-1" here is not a pinned resource region -- it's S3's own quirk that
    # CreateBucket rejects an explicit LocationConstraint for that region; the bucket
    # still lands in ctx.region either way.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _run_job_until_role_propagates(
    glue, job_name: str, arguments: dict[str, str], overall_timeout_s: float = 240.0, retry_interval_s: float = 15.0
) -> dict:
    """Start-and-poll a job run, retrying with a FRESH run only while the failure is the
    specific "should be given assume role permissions" message Glue returns when the
    freshly-attached role policy has not yet propagated to the service. Any other
    failure is returned immediately rather than retried away. `start_job_run` itself is
    also retried: Glue's own concurrency bookkeeping for this job can briefly still count
    the just-failed run, so a retry lands a `ConcurrentRunsExceededException`."""
    deadline = time.monotonic() + overall_timeout_s
    last: dict = {}
    while True:
        try:
            run_id = glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except Exception as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"start_job_run kept failing: {exc}") from exc
            time.sleep(retry_interval_s)
            continue
        remaining = max(30.0, deadline - time.monotonic())
        last = _poll_job_run_terminal(glue, job_name, run_id, timeout_s=remaining)
        if last["JobRunState"] == "SUCCEEDED":
            return last
        if "assume role" not in (last.get("ErrorMessage") or "").lower() or time.monotonic() >= deadline:
            return last
        time.sleep(retry_interval_s)


def _poll_job_run_terminal(glue, job_name: str, run_id: str, timeout_s: float = 300.0) -> dict:
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if last["JobRunState"] in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"job run never reached a terminal state within {timeout_s}s: {last}")


def _wait_for_message_body(sqs, queue_url: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
