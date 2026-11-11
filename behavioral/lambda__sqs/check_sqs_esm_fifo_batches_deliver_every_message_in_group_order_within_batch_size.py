"""sqs-esm-fifo-batches-deliver-every-message-in-group-order-within-batch-size."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sqs-esm-fifo-batches-deliver-every-message-in-group-order-within-batch-size"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sqs"]

BATCH_SIZE = 3
N_MESSAGES = 7

_HANDLER = """
import json
import os

import boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    records = event.get("Records", [])
    _sqs.send_message(
        QueueUrl=os.environ["SINK"],
        MessageBody=json.dumps([r["body"] for r in records]),
        MessageGroupId="sim2real-sink",
        MessageDeduplicationId=context.aws_request_id,
    )
    return {"batchItemFailures": []}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An ESM on a FIFO queue's single message group delivers every message at least once, in
    send order within and across batches, and never hands the function more than BatchSize records.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
    """
    src = _create_queue(ctx, "src", fifo=True)
    # A FIFO sink keeps the invocations in the order the function ran them.
    sink = _create_queue(ctx, "sink", fifo=True)
    role_arn = _create_role(ctx, src["arn"], sink["arn"])
    fn = _create_function(ctx, role_arn, env={"SINK": sink["url"]})

    sent_bodies = [f"sim2real-msg-{i}" for i in range(N_MESSAGES)]
    sqs = ctx.client("sqs")
    for i, body in enumerate(sent_bodies):
        sqs.send_message(QueueUrl=src["url"], MessageBody=body, MessageGroupId="sim2real-one-group",
                         MessageDeduplicationId=f"sim2real-dedup-{i}")

    _create_esm(ctx, src["arn"], fn["name"], BatchSize=BATCH_SIZE)

    batches = _wait_for(
        ctx,
        lambda: _drain(ctx, sink["url"]),
        lambda got: {body for batch in got for body in batch} >= set(sent_bodies),
        timeout_s=120, interval_s=2.0,
        description=f"all {N_MESSAGES} sent messages delivered to the function",
    )

    sizes = [len(b) for b in batches]
    assert all(1 <= n <= BATCH_SIZE for n in sizes), (
        f"every invocation must carry 1..{BATCH_SIZE} records (BatchSize={BATCH_SIZE}); "
        f"batch sizes were {sizes!r}"
    )
    for batch in batches:
        order = [sent_bodies.index(body) for body in batch]
        assert order == sorted(order) and len(set(order)) == len(order), (
            f"records within one batch must keep the group's send order; batch held {batch!r}"
        )
    first_seen: list[str] = []
    for body in (body for batch in batches for body in batch):
        if body not in first_seen:
            first_seen.append(body)
    assert first_seen == sent_bodies, (
        f"across invocations the records must first arrive in send order {sent_bodies!r}, "
        f"got {first_seen!r} from batches {batches!r}"
    )


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_for(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe(), accumulating; return once predicate(accumulated) holds, else TimeoutError."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    accumulated: list[list[str]] = []
    while True:
        accumulated.extend(probe())
        if predicate(accumulated):
            return accumulated
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{description} not observed within {timeout_s:.0f}s; saw {accumulated!r}")
        time.sleep(interval_s)


def _create_queue(ctx, suffix: str, fifo: bool = False) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-q-{suffix}-")
    kwargs: dict[str, Any] = {"QueueName": name, "tags": {"sim2real:managed": "true"}}
    if fifo:
        kwargs["QueueName"] = f"{name}.fifo"
        kwargs["Attributes"] = {"FifoQueue": "true"}
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx, src_arn: str, sink_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    statements = [
        {"Effect": "Allow",
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
         "Resource": src_arn},
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink_arn},
    ]
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
                             "NoSuchEntity"))
    return role["Arn"]


def _create_function(ctx, role_arn: str, env: dict[str, str]) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER)
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
    kwargs: dict[str, Any] = dict(
        FunctionName=name, Runtime="python3.13", Handler="index.handler", Role=role_arn,
        Code={"ZipFile": buf.getvalue()}, Timeout=30, MemorySize=128, Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err["Message"]:
                return None
            raise

    resp = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
                description="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name).get("State"),
         lambda s: s == "Active", timeout_s=90, interval_s=3,
         description=f"function {name} Active")
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_esm(ctx, source_arn: str, function_name: str, **kwargs) -> str:
    lam = ctx.client("lambda")
    params = dict(EventSourceArn=source_arn, FunctionName=function_name, Enabled=True, **kwargs)
    uuid_ = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid_),
                             "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_event_source_mapping(UUID=uuid_)["State"], lambda s: s == "Enabled",
         timeout_s=90, interval_s=3, description=f"ESM {uuid_} Enabled")
    return uuid_


def _drain(ctx, queue_url: str, wait_s: int = 3) -> list[list[str]]:
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _poll(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result) holds; raise TimeoutError at the capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s; last saw {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
