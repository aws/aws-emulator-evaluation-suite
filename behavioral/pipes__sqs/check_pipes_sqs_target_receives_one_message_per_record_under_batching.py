"""pipes-sqs-target-receives-one-message-per-record-under-batching."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-sqs-target-receives-one-message-per-record-under-batching"

GROUP = "data-batching"

SERVICES = ["pipes", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe with BatchSize=10 and a 20 s batching window delivers each source record to an SQS
    target as its own single-record message, never a JSON array, and every record arrives.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
    """
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    source = _create_queue(ctx, VisibilityTimeout="120")
    target = _create_queue(ctx)
    role = _create_pipe_role(ctx, source["arn"], target["arn"])

    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={
            "SqsQueueParameters": {"BatchSize": 10, "MaximumBatchingWindowInSeconds": 20}
        },
    )
    described = pipes.describe_pipe(Name=pipe)
    assert described["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 10, (
        f"describe_pipe must echo the configured BatchSize 10, got "
        f"{described['SourceParameters']!r}"
    )

    nonce = _xname(ctx, "batch")
    sqs.send_message_batch(
        QueueUrl=source["url"],
        Entries=[
            {"Id": f"e{i}", "MessageBody": json.dumps({"i": i, "nonce": nonce})}
            for i in range(10)
        ],
    )

    seen: dict[int, int] = {}
    per_delivery: list[int] = []
    arrays: list[Any] = []
    foreign: list[Any] = []
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline and set(seen) != set(range(10)):
        resp = sqs.receive_message(
            QueueUrl=target["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target["url"], ReceiptHandle=msg["ReceiptHandle"])
            payload = json.loads(msg["Body"])
            if isinstance(payload, list):
                arrays.append(payload)
                records = payload
            else:
                records = [payload]
            per_delivery.append(len(records))
            for rec in records:
                inner = json.loads(rec["body"]) if isinstance(rec, dict) and "body" in rec else rec
                if not isinstance(inner, dict) or inner.get("nonce") != nonce:
                    foreign.append(inner)
                    continue
                seen[inner["i"]] = seen.get(inner["i"], 0) + 1

    assert set(seen) == set(range(10)), (
        f"every source record must reach the target; missing indices "
        f"{sorted(set(range(10)) - set(seen))!r}, observed {dict(sorted(seen.items()))!r} across "
        f"deliveries of size {per_delivery!r} (pipe {pipe!r})"
    )
    assert foreign == [], (
        f"the target must carry only this run's records; it also carried {foreign!r}"
    )
    # Batching bounds the poll, not the target invocation: SQS takes one payload per call.
    assert arrays == [], (
        f"an SQS target receives ONE record per message, so no delivered body may be a JSON array "
        f"of records; {len(arrays)} array-shaped delivery/deliveries arrived: {arrays!r} -- this is "
        f"the emulator that forwards the polled batch straight through to SendMessage"
    )
    assert set(per_delivery) == {1}, (
        f"every target delivery must carry exactly one record envelope; observed sizes "
        f"{per_delivery!r}"
    )

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    # IAM propagation exposes no condition to poll -- no API reports that a role has become
    # assumable -- so the wait for that lives entirely in _create_pipe's bounded assume-role retry.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_pipe_role(ctx, source_arn: str, target_arn, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue(s)."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for. Returns the pipe name.

    Pipes assumes the role at create time, so only the two assume-role messages are retried.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(8):
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
