"""esm-no-message-is-lost-when-the-handler-throws-on-first-delivery."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-no-message-is-lost-when-the-handler-throws-on-first-delivery"

GROUP = "event-source-mapping"

SERVICES = ["lambda"]

_N = 6
# maxReceiveCount is deliberately well above the two deliveries this check provokes: the DLQ is
# here as the LOSS DETECTOR (anything that ends up there was given up on), not as the destination.
_MAX_RECEIVE = 5
_VISIBILITY_S = 10

# Runs INSIDE the deployed function. First sight of a message (ApproximateReceiveCount == 1) is
# refused by raising; any later sight is processed. Both halves print per-message evidence, so the
# check can prove the SAME body was both dropped and recovered.
_HANDLER = """
import json

def lambda_handler(event, context):
    records = event.get("Records", [])
    first = []
    for rec in records:
        rc = int(rec.get("attributes", {}).get("ApproximateReceiveCount", "0"))
        line = {"body": rec["body"], "rc": rc, "msg_id": rec.get("messageId")}
        if rc <= 1:
            first.append(line)
            print("THREW " + json.dumps(line, sort_keys=True))
        else:
            print("OKAY " + json.dumps(line, sort_keys=True))
    if first:
        raise RuntimeError("refusing first delivery of " + json.dumps(
            [r["body"] for r in first], sort_keys=True))
    ret = {"processed": [r["body"] for r in records], "count": len(records)}
    print("RET " + json.dumps(ret, sort_keys=True))
    return ret
"""


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A handler that throws returns its messages to the queue: each of N messages is refused on
    first delivery, redelivered with ApproximateReceiveCount > 1 and processed, the source queue
    drains to zero, and the DLQ stays empty.
    """
    sqs = ctx.client("sqs")

    dlq = _create_queue(ctx)
    src = _create_queue(
        ctx,
        VisibilityTimeout=str(_VISIBILITY_S),
        RedrivePolicy=json.dumps({"deadLetterTargetArn": dlq["arn"], "maxReceiveCount": _MAX_RECEIVE}),
    )
    fn = _create_lambda(
        ctx,
        _HANDLER,
        permissions=[{"Action": _POLL_ACTIONS, "Resource": src["arn"]}],
        timeout=10,
    )

    esm = _create_esm(
        ctx,
        EventSourceArn=src["arn"],
        FunctionName=fn["name"],
        # BatchSize 1 keeps the claim per message; a mixed batch would make delivery counts
        # depend on batching. Duplicates stay allowed: SQS standard queues are at-least-once.
        BatchSize=1,
        Enabled=True,
    )
    _wait_esm_state(ctx, esm["UUID"], "Enabled")

    since_ms = int(time.time() * 1000) - 5_000
    run_id = ctx.unique_name("payload-")
    sent = [f"{run_id}-{i:02d}" for i in range(_N)]
    for body in sent:
        sqs.send_message(QueueUrl=src["url"], MessageBody=body)

    threw = _await_lines(
        ctx,
        fn["name"],
        since_ms,
        "THREW ",
        lambda ls: {r["body"] for r in _records(ls, "THREW ")} >= set(sent),
        timeout_s=150.0,
    )
    threw_bodies = {r["body"] for r in _records(threw, "THREW ")}
    assert threw_bodies >= set(sent), (
        f"only {len(threw_bodies)} of {_N} messages ever reached the handler at all: the mapping "
        f"delivered {sorted(threw_bodies)!r}, missing {sorted(set(sent) - threw_bodies)!r}"
    )

    okay = _await_lines(
        ctx,
        fn["name"],
        since_ms,
        "OKAY ",
        lambda ls: {r["body"] for r in _records(ls, "OKAY ")} >= set(sent),
        timeout_s=180.0,
    )
    okay_records = _records(okay, "OKAY ")
    okay_bodies = {r["body"] for r in okay_records}
    dropped = sorted(set(sent) - okay_bodies)
    assert not dropped, (
        f"{len(dropped)} message(s) were handed to a handler that threw and then NEVER came back: "
        f"{dropped!r}. A failed invocation must return its messages to the queue, not consume them. "
        f"Recovered bodies were {sorted(okay_bodies)!r}"
    )
    stale = [r for r in okay_records if r["body"] in sent and r["rc"] <= 1]
    assert not stale, (
        "a body was processed on a delivery reporting ApproximateReceiveCount <= 1, so it was never "
        f"actually redelivered -- the receive count is not being incremented: {stale!r}"
    )

    visible, in_flight = _await_counts(ctx, src["url"], (0, 0), timeout_s=150.0)
    assert (visible, in_flight) == (0, 0), (
        f"after every message was successfully processed the source queue still holds "
        f"visible={visible}, in_flight={in_flight}; the successful delivery did not delete them"
    )

    dlq_visible, dlq_in_flight = _queue_counts(ctx, dlq["url"])
    assert (dlq_visible, dlq_in_flight) == (0, 0), (
        f"the redrive target holds visible={dlq_visible}, in_flight={dlq_in_flight}. With "
        f"maxReceiveCount={_MAX_RECEIVE} against two deliveries per message, nothing should have "
        f"been abandoned -- anything here is a message the mapping gave up on: "
        f"{[m.get('Body') for m in _drain(ctx, dlq['url'], window_s=10.0)]!r}"
    )

_PREFIX = "sim2real-esm-"

_POLL_ACTIONS = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, Attributes=dict(attrs), tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _queue_counts(ctx, url: str) -> tuple[int, int]:
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (
        int(attrs.get("ApproximateNumberOfMessages", "-1")),
        int(attrs.get("ApproximateNumberOfMessagesNotVisible", "-1")),
    )


def _await_counts(ctx, url: str, want: tuple[int, int], *, timeout_s=120.0) -> tuple[int, int]:
    """Poll the queue's depth until it reaches `want`, then return the LAST reading either way.
    The caller asserts, so a timeout reports the real numbers instead of raising a bare timeout."""
    deadline = time.monotonic() + timeout_s
    last = _queue_counts(ctx, url)
    while time.monotonic() < deadline:
        last = _queue_counts(ctx, url)
        if last == want:
            return last
        time.sleep(3)
    return last


def _handler_lines(ctx, fn_name: str, since_ms: int, prefix: str) -> list[str]:
    """Every stdout line the handler emitted since `since_ms` that starts with `prefix`.

    Paginated; keyed on (eventId, line) so repeated polls do not double-count real redeliveries."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    found: dict[tuple[str, str], str] = {}
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=since_ms
        )
        for page in pages:
            for event in page.get("events", []):
                for raw in event.get("message", "").splitlines():
                    line = raw.strip()
                    if line.startswith(prefix):
                        found[(event["eventId"], line)] = line
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return list(found.values())


def _await_lines(ctx, fn_name: str, since_ms: int, prefix: str, predicate, *, timeout_s=180.0):
    """Poll the log group until predicate(lines) holds; return the last read either way."""
    deadline = time.monotonic() + timeout_s
    lines = _handler_lines(ctx, fn_name, since_ms, prefix)
    while time.monotonic() < deadline:
        lines = _handler_lines(ctx, fn_name, since_ms, prefix)
        if predicate(lines):
            return lines
        time.sleep(5)
    return lines


def _records(lines: list[str], prefix: str) -> list[dict[str, Any]]:
    """Parse `PREFIX <json>` evidence lines structurally."""
    return [json.loads(line[len(prefix) :]) for line in lines]


def _create_role(ctx, inline_policy: dict[str, Any]) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, group: str, *, rounds=4, settle_s=4.0) -> None:
    """Delete the function's log group, re-deleting if a late-flushed stream recreates it.

    delete_function leaves /aws/lambda/<fn>; bounded rounds, raising if it never converges."""
    logs = ctx.client("logs")
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(settle_s)
        present = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in present):
            return
    raise RuntimeError(f"log group {group} reappeared after {rounds} delete rounds")


def _create_lambda(ctx, handler_code: str, permissions=None, env=None, timeout=30) -> dict[str, str]:
    """Create a Lambda whose execution role is scoped to `permissions` (logs always allowed).

    Teardown is registered so LIFO deletes the function, then reaps its log group, then the role."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        resource = perm["Resource"] if isinstance(perm["Resource"], list) else [perm["Resource"]]
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(ctx, {"Version": "2012-10-17", "Statement": statements})

    name = _xname(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))

    lam = ctx.client("lambda")
    code = textwrap.dedent(handler_code)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role["arn"],
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    # IAM role propagation exposes no condition to poll -- no API reports that a fresh role has
    # become assumable -- so the bounded retry on the one error code it raises is what makes this
    # correct, and the sleep only makes it cheaper.
    deadline = time.monotonic() + 90
    last: Exception | None = None
    arn = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(4)
    assert arn is not None, f"CreateFunction never accepted the fresh role within 90s: {last!r}"
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=90.0,
        interval_s=2.0,
        description=f"Lambda {name} State=Active",
    )
    return {"name": name, "arn": arn}


def _create_esm(ctx, **kwargs: Any) -> dict[str, Any]:
    """CreateEventSourceMapping VALIDATES the execution role's sqs:ReceiveMessage grant, so it is
    refused until the fresh role has propagated. Bounded retry on that one code."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            esm = lam.create_event_source_mapping(**kwargs)
            uuid_ = esm["UUID"]
            ctx.on_cleanup(lambda u=uuid_: _delete_esm(ctx, u))
            return esm
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(5)
    raise AssertionError(f"CreateEventSourceMapping never accepted the role within 90s: {last!r}")


def _delete_esm(ctx, uuid_: str) -> None:
    try:
        ctx.client("lambda").delete_event_source_mapping(UUID=uuid_)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_esm_state(ctx, uuid_: str, want: str, *, timeout_s=210.0) -> None:
    """Wait for the ESM to report `want`; asserting delivery before the poller starts is a race."""
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_).get("State"),
        lambda s: s == want,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"ESM {uuid_} State={want}",
    )


def _drain(ctx, url: str, *, window_s=20.0, max_total=25) -> list[dict[str, Any]]:
    """Long-poll a queue over a bounded window and return EVERY message seen, deleting as it goes.

    An empty return is only meaningful beside a positive observation elsewhere in the check."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
