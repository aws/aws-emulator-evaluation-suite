"""glue-job-role-without-sqs-send-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "glue-job-role-without-sqs-send-permission-negative"
GROUP = "overly-permissive"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job whose role lacks sqs:SendMessage ends FAILED with an access-denied error and sends
    nothing, while the same job with the permission SUCCEEDS and its "glue-job-complete" message
    arrives.
    """
    glue = ctx.client("glue")
    sqs = ctx.client("sqs")
    s3 = ctx.client("s3")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-glue-noperm-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    bucket = _create_aws_glue_bucket(ctx)
    script_key = "notify.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT.encode())

    # --- Negative: role has no sqs:SendMessage permission ---
    no_perm_role_arn = _create_glue_role(ctx, "sim2real-glue-noperm-role-", attach_sqs_send=None)
    bad_job_name = ctx.unique_name("sim2real-glue-noperm-job-")
    glue.create_job(
        Name=bad_job_name,
        Role=no_perm_role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=bad_job_name))

    bad_final = _run_job_until_role_ready(
        glue, bad_job_name, {"--queue_url": queue_url, "--region": ctx.region}
    )
    assert bad_final["JobRunState"] == "FAILED", f"expected FAILED, got {bad_final.get('JobRunState')}"
    error_message = (bad_final.get("ErrorMessage") or "").lower()
    assert "accessdenied" in error_message or "access denied" in error_message, (
        f"expected an AccessDenied failure reason, got: {bad_final.get('ErrorMessage')!r}"
    )
    assert _no_message_arrives(sqs, queue_url, timeout_s=15), "message arrived despite missing permission"

    # --- Positive control: identical role, but with sqs:SendMessage ---
    with_perm_role_arn = _create_glue_role(ctx, "sim2real-glue-withperm-role-", attach_sqs_send=queue_arn)
    good_job_name = ctx.unique_name("sim2real-glue-withperm-job-")
    glue.create_job(
        Name=good_job_name,
        Role=with_perm_role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{bucket}/{script_key}"},
        MaxCapacity=0.0625,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=good_job_name))

    good_final = _run_job_until_role_ready(
        glue, good_job_name, {"--queue_url": queue_url, "--region": ctx.region}
    )
    assert good_final["JobRunState"] == "SUCCEEDED", (
        f"positive control job run failed: {good_final.get('ErrorMessage')}"
    )
    body = _wait_for_message_body(sqs, queue_url, timeout_s=30)
    assert body == "glue-job-complete"


def _create_glue_role(ctx: Any, prefix: str, attach_sqs_send: str | None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
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

    if attach_sqs_send is not None:
        send_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": attach_sqs_send}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="sqs-send", PolicyDocument=json.dumps(send_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))
    return role_arn


def _create_aws_glue_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("aws-glue-sim2real-")
    if ctx.region == "us-east-1":  # S3 rejects an explicit LocationConstraint for this one region
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


def _run_job_until_role_ready(glue, job_name: str, arguments: dict[str, str], timeout_s: float = 180.0) -> dict:
    """Retries the run when Glue reports the just-created role's trust policy has not
    yet propagated (InvalidInputException, "should be given assume role permissions for
    Glue Service") -- a genuine IAM/Glue eventual-consistency gap, distinct from the
    AccessDenied this check exists to assert."""
    deadline = time.monotonic() + timeout_s
    while True:
        run_id = _start_job_run_with_retry(glue, job_name, arguments, deadline)
        final = _poll_job_run_terminal(glue, job_name, run_id, timeout_s=300)
        message = (final.get("ErrorMessage") or "").lower()
        if "assume role permissions for glue service" in message and time.monotonic() < deadline:
            time.sleep(2)
            continue
        return final


def _start_job_run_with_retry(glue, job_name: str, arguments: dict[str, str], deadline: float) -> str:
    """Glue does not release a job's concurrency slot the instant a run reaches a
    terminal state; starting the next run immediately after can hit
    ConcurrentRunsExceededException for a few seconds. Retry only that specific,
    transient code -- anything else is a real defect and must raise."""
    from botocore.exceptions import ClientError

    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConcurrentRunsExceededException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"start_job_run kept hitting ConcurrentRunsExceededException: {last_err}")


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


def _no_message_arrives(sqs, queue_url: str, timeout_s: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        if resp.get("Messages"):
            return False
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
