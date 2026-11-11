"""cli-delete-queue-then-notification-fails-negative."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-delete-queue-then-notification-fails-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteQueue.html
@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Referencing a deleted SQS queue in a bucket notification config is rejected and does not persist."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-delq-bkt-")
    live_queue_name = ctx.unique_name("sim2real-delq-live-")
    doomed_queue_name = ctx.unique_name("sim2real-delq-doomed-")

    _create_bucket_cli(ctx, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    live_url, live_arn = _create_queue_cli(ctx, live_queue_name)
    _authorize_s3_to_send(ctx, live_url, live_arn, bucket_arn)

    working_cfg = {"QueueConfigurations": [{"QueueArn": live_arn, "Events": ["s3:ObjectCreated:*"]}]}
    _run_aws(
        ctx,
        "s3api",
        "put-bucket-notification-configuration",
        "--bucket",
        bucket,
        "--notification-configuration",
        json.dumps(working_cfg),
    )
    applied = _run_aws(ctx, "s3api", "get-bucket-notification-configuration", "--bucket", bucket)
    applied_arn = applied.get("QueueConfigurations", [{}])[0].get("QueueArn")
    assert applied_arn == live_arn, (
        f"positive control: the live-queue config must land, expected {live_arn!r} got {applied_arn!r}"
    )

    doomed_url = _run_aws(ctx, "sqs", "create-queue", "--queue-name", doomed_queue_name, "--tags", "sim2real=true")[
        "QueueUrl"
    ]
    doomed_arn = _run_aws(ctx, "sqs", "get-queue-attributes", "--queue-url", doomed_url, "--attribute-names", "QueueArn")[
        "Attributes"
    ]["QueueArn"]
    _run_aws(ctx, "sqs", "delete-queue", "--queue-url", doomed_url)

    broken_cfg = {"QueueConfigurations": [{"QueueArn": doomed_arn, "Events": ["s3:ObjectCreated:*"]}]}
    code, message = _error(
        lambda: _run_aws(
            ctx,
            "s3api",
            "put-bucket-notification-configuration",
            "--bucket",
            bucket,
            "--notification-configuration",
            json.dumps(broken_cfg),
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for a deleted-queue target, got {code!r}"
    assert message == "Unable to validate the following destination configurations", (
        f"unexpected InvalidArgument message for a deleted-queue target: {message!r}"
    )

    after = _run_aws(ctx, "s3api", "get-bucket-notification-configuration", "--bucket", bucket)
    after_queue_arns = [q["QueueArn"] for q in after.get("QueueConfigurations", [])]
    assert after_queue_arns == [live_arn], (
        f"the rejected config must not have replaced the working one; got {after_queue_arns}"
    )

    # Restore leg: an SQS queue ARN is name-derived (no unique suffix), so recreating a queue
    # under the doomed name reinstates the identical ARN. Once the target exists again, the
    # SAME notification config that was just rejected must be accepted.
    revived_url, revived_arn = _recreate_queue_cli(ctx, doomed_queue_name)
    assert revived_arn == doomed_arn, (
        f"recreating the queue under its old name must reuse the same ARN; expected {doomed_arn!r} got {revived_arn!r}"
    )
    _authorize_s3_to_send(ctx, revived_url, revived_arn, bucket_arn)

    _run_aws(
        ctx,
        "s3api",
        "put-bucket-notification-configuration",
        "--bucket",
        bucket,
        "--notification-configuration",
        json.dumps(broken_cfg),
    )
    restored = _run_aws(ctx, "s3api", "get-bucket-notification-configuration", "--bucket", bucket)
    restored_arns = [q["QueueArn"] for q in restored.get("QueueConfigurations", [])]
    assert restored_arns == [doomed_arn], (
        f"the identical call must succeed once its target queue exists again; expected [{doomed_arn!r}] got {restored_arns}"
    )


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


def _error(fn):
    """Run `fn` (a CLI call raising AssertionError on failure) and return the AWS error's (code,
    message) from the CLI's stderr. An unexpected SUCCESS raises rather than returning a falsy
    sentinel."""
    try:
        result = fn()
    except AssertionError as exc:
        # aws CLI error lines look like: "An error occurred (InvalidArgument) when calling the X operation: <message>"
        marker = "An error occurred ("
        for line in str(exc).splitlines():
            idx = line.find(marker)
            if idx == -1 or ") when calling the " not in line:
                continue
            rest = line[idx + len(marker):]
            code, tail = rest.split(") when calling the ", 1)
            return code, tail.split(" operation: ", 1)[1]
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket_cli(ctx, name):
    args = ["s3api", "create-bucket", "--bucket", name, "--region", ctx.region]
    if ctx.region != "us-east-1":
        # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; this is
        # an API quirk comparison, not a hardcoded target region (ctx.region drives the call).
        args += ["--create-bucket-configuration", f"LocationConstraint={ctx.region}"]
    _run_aws(ctx, *args)
    ctx.client("s3").get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    _run_aws(ctx, "s3api", "put-bucket-tagging", "--bucket", name, "--tagging", "TagSet=[{Key=sim2real,Value=true}]")
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))


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
    out = _run_aws(ctx, "sqs", "create-queue", "--queue-name", name, "--tags", "sim2real=true")
    url = out["QueueUrl"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "sqs", "delete-queue", "--queue-url", url, check=False))
    arn = _run_aws(ctx, "sqs", "get-queue-attributes", "--queue-url", url, "--attribute-names", "QueueArn")[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _recreate_queue_cli(ctx, name, *, timeout_s=90.0, interval_s=5.0):
    """SQS enforces a ~60s cooldown before a deleted queue's name can be reused
    (AWS.SimpleQueueService.QueueDeletedRecently); retry create-queue until it clears."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            out = _run_aws(ctx, "sqs", "create-queue", "--queue-name", name, "--tags", "sim2real=true")
            break
        except AssertionError as exc:
            if "QueueDeletedRecently" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    url = out["QueueUrl"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "sqs", "delete-queue", "--queue-url", url, check=False))
    arn = _run_aws(ctx, "sqs", "get-queue-attributes", "--queue-url", url, "--attribute-names", "QueueArn")[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _authorize_s3_to_send(ctx, queue_url, queue_arn, bucket_arn):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
