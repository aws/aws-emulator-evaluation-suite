"""cli-upload-object-poll-queue-verify-message-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-upload-object-poll-queue-verify-message-positive"
GROUP = "delivery"
SERVICES = ["lambda", "s3", "sqs"]

# Every resource carries `sim2real:managed=true` so a tag-based sweep (Resource Groups Tagging API)
# can find and delete anything a failed teardown leaves behind.
_TAGS = {"sim2real:managed": "true", "sim2real": "cli-upload-object-poll-queue"}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws s3 cp` upload triggers a bucket-notification message, confirmed via `aws sqs receive-message`."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-upl-bkt-")
    queue_name = ctx.unique_name("sim2real-upl-q-")

    _create_bucket_cli(ctx, bucket)
    queue_url, queue_arn = _create_queue_cli(ctx, queue_name)

    bucket_arn = f"arn:aws:s3:::{bucket}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": bucket_arn}},
            }
        ],
    }
    _run_aws(
        ctx,
        "sqs",
        "set-queue-attributes",
        "--queue-url",
        queue_url,
        "--attributes",
        json.dumps({"Policy": json.dumps(policy)}),
    )

    notif_cfg = {"QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]}
    _run_aws(
        ctx,
        "s3api",
        "put-bucket-notification-configuration",
        "--bucket",
        bucket,
        "--notification-configuration",
        json.dumps(notif_cfg),
    )

    key = "cli-upload-test.txt"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("upload-cli-content")
        local_path = f.name
    try:
        _run_aws(ctx, "s3", "cp", local_path, f"s3://{bucket}/{key}")
    finally:
        os.unlink(local_path)

    found = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and found is None:
        out = _run_aws(
            ctx,
            "sqs",
            "receive-message",
            "--queue-url",
            queue_url,
            "--wait-time-seconds",
            "10",
            "--max-number-of-messages",
            "5",
        )
        for msg in out.get("Messages", []):
            body = json.loads(msg["Body"])
            for rec in body.get("Records", []):
                s3info = rec.get("s3", {})
                if s3info.get("object", {}).get("key") == key:
                    found = rec
            _run_aws(ctx, "sqs", "delete-message", "--queue-url", queue_url, "--receipt-handle", msg["ReceiptHandle"])

    if found is None:
        raise AssertionError("expected S3 notification message never arrived in queue within 90s")
    found_bucket = found["s3"]["bucket"]["name"]
    found_key = found["s3"]["object"]["key"]
    found_event = found.get("eventName", "")
    assert found_bucket == bucket, f"expected notification for bucket {bucket!r}, got {found_bucket!r}"
    assert found_key == key, f"expected notification for key {key!r}, got {found_key!r}"
    assert found_event.startswith("ObjectCreated:"), (
        f"expected an ObjectCreated:* eventName for a CLI upload, got {found_event!r}"
    )


# ===== helpers =====


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["AWS_PAGER"] = ""
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_bucket_cli(ctx, name):
    args = ["s3api", "create-bucket", "--bucket", name, "--region", ctx.region]
    if ctx.region != "us-east-1":
        args += ["--create-bucket-configuration", f"LocationConstraint={ctx.region}"]
    _run_aws(ctx, *args)
    ctx.client("s3").get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    tag_set = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
    _run_aws(ctx, "s3api", "put-bucket-tagging", "--bucket", name, "--tagging", json.dumps({"TagSet": tag_set}))


def _delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        for o in s3.list_objects_v2(Bucket=name).get("Contents", []):
            s3.delete_object(Bucket=name, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_queue_cli(ctx, name):
    tags_arg = ",".join(f"{k}={v}" for k, v in _TAGS.items())
    out = _run_aws(ctx, "sqs", "create-queue", "--queue-name", name, "--tags", tags_arg)
    url = out["QueueUrl"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "sqs", "delete-queue", "--queue-url", url, check=False))
    arn = _run_aws(ctx, "sqs", "get-queue-attributes", "--queue-url", url, "--attribute-names", "QueueArn")[
        "Attributes"
    ]["QueueArn"]
    return url, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
