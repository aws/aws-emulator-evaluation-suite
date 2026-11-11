"""cli-update-event-source-mapping-batch-size-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-update-event-source-mapping-batch-size-positive"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "s3", "sqs"]

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]

HANDLER_SRC = '''
import boto3, json, os

def handler(event, context):
    s3 = boto3.client("s3")
    out_bucket = os.environ["OUT_BUCKET"]
    bodies = [r.get("body") for r in event.get("Records", [])]
    count = len(bodies)
    key = "batches/" + context.aws_request_id + ".json"
    s3.put_object(Bucket=out_bucket, Key=key,
                  Body=json.dumps({"count": count, "bodies": bodies}).encode())
    return {"count": count}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating an ESM's BatchSize via the CLI is reflected in subsequent invocation batch sizes."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-bs-out-")
    queue_name = ctx.unique_name("sim2real-bs-q-")
    func_name = ctx.unique_name("sim2real-bs-fn-")

    _create_bucket_cli(ctx, bucket)
    queue_url, queue_arn = _create_queue_cli(ctx, queue_name)
    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": queue_arn,
                },
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
            ],
        },
    )
    _create_function_cli(ctx, func_name, role_arn, HANDLER_SRC, env={"OUT_BUCKET": bucket})

    create_out = _run_aws(
        ctx,
        "lambda",
        "create-event-source-mapping",
        "--event-source-arn",
        queue_arn,
        "--function-name",
        func_name,
        "--batch-size",
        "1",
        "--tags",
        "sim2real:managed=true,sim2real:prefix=sim2real-bs",
    )
    uuid_ = create_out["UUID"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-event-source-mapping", "--uuid", uuid_, check=False))
    _wait_esm(ctx, uuid_, lambda m: m.get("State") == "Enabled", timeout_s=_budget_s(ctx, 120.0))

    sqs = ctx.client("sqs")
    for i in range(3):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"phase1-{i}")

    counts_phase1, _ = _poll_batch_counts(ctx, bucket, "batches/", min_total=3, marker="phase1-",
                                          timeout_s=_budget_s(ctx, 120.0))
    assert all(c == 1 for c in counts_phase1), f"BatchSize=1 should cap every invocation at 1 record, got {counts_phase1}"

    _run_aws(ctx, "lambda", "update-event-source-mapping", "--uuid", uuid_, "--batch-size", "10")
    _wait_esm(ctx, uuid_, lambda m: m.get("State") == "Enabled" and m.get("BatchSize") == 10,
              timeout_s=_budget_s(ctx, 120.0))

    # The ESM's own reported BatchSize flips the instant the control plane accepts the update,
    # but the poller fleet actually pulling from SQS can lag behind that by tens of seconds
    # before it starts requesting the new BatchSize — a single burst sent right after the API
    # confirms BatchSize=10 can still arrive as singleton
    # invocations. Retry with a fresh burst (unique markers each attempt, so no double-count
    # across attempts) until batching is actually observed, bounded so a target that never
    # batches still fails rather than looping forever.
    # Each invocation is attributed to an attempt by the message bodies it received, never by
    # object timestamps.
    phase2_deadline = time.monotonic() + _budget_s(ctx, 200.0)
    counts_phase2: list[int] = []
    totals_phase2: list[int] = []
    attempt = 0
    while True:
        attempt += 1
        marker = f"phase2-{attempt}-"
        entries = [{"Id": str(i), "MessageBody": f"{marker}{i}"} for i in range(8)]
        sqs.send_message_batch(QueueUrl=queue_url, Entries=entries)
        counts_phase2, totals_phase2 = _poll_batch_counts(
            ctx, bucket, "batches/", min_total=8, marker=marker,
            timeout_s=min(60.0, max(0.0, phase2_deadline - time.monotonic())))
        if max(counts_phase2) > 1 or time.monotonic() >= phase2_deadline:
            break
        time.sleep(2)
    if max(counts_phase2) <= 1 and _budget_spent(ctx):
        raise TimeoutError("an invocation batching >1 record after BatchSize=10: the run budget ended first; not graded")

    # SQS standard queues are at-least-once: a message can be redelivered (e.g. if a poller
    # in flight with the old BatchSize overlaps the transition), so allow sum >= 8 rather than
    # requiring an exact match — the behavior under test is the batching width, not dedup.
    assert sum(counts_phase2) >= 8, f"expected at least 8 phase-2 messages processed, got {counts_phase2}"
    assert max(counts_phase2) > 1, (
        f"expected at least one invocation to batch >1 records after raising BatchSize to 10, "
        f"got {counts_phase2} after {attempt} attempt(s)"
    )
    assert max(totals_phase2) <= 10, (
        f"BatchSize=10 should cap every invocation at 10 records, got {totals_phase2}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; every other
    # region requires it. Not a region pin — ctx.region drives the bucket's actual region.
    if ctx.region != "us-east-1":
        args += ["--create-bucket-configuration", f"LocationConstraint={ctx.region}"]
    _run_aws(ctx, *args)
    s3 = ctx.client("s3")
    s3.get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 50})
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": _MANAGED_TAGS + [{"Key": "sim2real:prefix", "Value": "sim2real-bs-out"}]},
    )
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
    out = _run_aws(ctx, "sqs", "create-queue", "--queue-name", name)
    url = out["QueueUrl"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "sqs", "delete-queue", "--queue-url", url, check=False))
    ctx.client("sqs").tag_queue(
        QueueUrl=url, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-bs-q"}
    )
    arn = _run_aws(ctx, "sqs", "get-queue-attributes", "--queue-url", url, "--attribute-names", "QueueArn")[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _make_zip_file(handler_src):
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("index.py", handler_src)
    return path


def _create_lambda_role(ctx, inline_policy=None, managed_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=_MANAGED_TAGS + [{"Key": "sim2real:prefix", "Value": "sim2real-role"}],
    )["Role"]
    role_arn = role["Arn"]

    def _cleanup_role():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for arn in managed_arns or []:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if inline_policy:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=f"{role_name}-inline")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    for arn in managed_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName=f"{role_name}-inline", PolicyDocument=json.dumps(inline_policy))
    return role_arn


def _wait_function_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active in {timeout_s}s")


def _create_function_cli(ctx, name, role_arn, handler_src, env=None, timeout=30):
    zip_path = _make_zip_file(handler_src)
    try:
        args = [
            "lambda",
            "create-function",
            "--function-name",
            name,
            "--runtime",
            "python3.12",
            "--role",
            role_arn,
            "--handler",
            "index.handler",
            "--zip-file",
            f"fileb://{zip_path}",
            "--timeout",
            str(timeout),
            "--tags",
            "sim2real:managed=true,sim2real:prefix=sim2real-bs-fn",
        ]
        if env:
            args += ["--environment", json.dumps({"Variables": env})]
        # A fresh role takes seconds to become assumable by Lambda; retry only that refusal.
        for _ in range(10):
            proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=30.0, check=False)
            if proc.returncode == 0 or "cannot be assumed by Lambda" not in proc.stderr:
                break
            time.sleep(3)
        if proc.returncode != 0:
            raise AssertionError(f"create-function failed (rc={proc.returncode}): {proc.stderr[-500:]}")
        out = json.loads(proc.stdout)
    finally:
        os.unlink(zip_path)
    func_arn = out["FunctionArn"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", name, check=False))
    _wait_function_active(ctx, name)
    return func_arn


def _wait_esm(ctx, uuid_, predicate, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _run_aws(ctx, "lambda", "get-event-source-mapping", "--uuid", uuid_)
        if predicate(last):
            return last
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"ESM {uuid_} to reach the expected state: the run budget ended first; not graded")
    raise AssertionError(f"ESM {uuid_} never satisfied predicate within {timeout_s}s (last={last})")


def _poll_batch_counts(ctx, bucket, prefix, min_total, marker, timeout_s=120.0):
    """Per invocation that received a `marker` message: (marker records, all records)."""
    s3 = ctx.client("s3")
    counts, totals = [], []
    deadline = time.monotonic() + timeout_s
    while True:
        counts, totals = [], []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            for o in page.get("Contents", []):
                body = json.loads(s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read())
                tagged = sum(1 for b in body.get("bodies", []) if str(b).startswith(marker))
                if tagged:
                    counts.append(tagged)
                    totals.append(body["count"])
        if sum(counts) >= min_total:
            return counts, totals
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"{min_total} processed {marker!r} records: the run budget ended first; not graded")
    raise AssertionError(f"expected total >= {min_total} processed records within {timeout_s}s, got {counts}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
