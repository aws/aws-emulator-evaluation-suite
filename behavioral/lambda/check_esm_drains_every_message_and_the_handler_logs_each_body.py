"""esm-drains-every-message-and-the-handler-logs-each-body."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-drains-every-message-and-the-handler-logs-each-body"

GROUP = "event-source-mapping"

SERVICES = ["lambda"]

_N = 12
_BATCH_SIZE = 5

# Runs inside the deployed function. Every evidence line is `TAG <json>` so it parses structurally.
_HANDLER = """
import json

def lambda_handler(event, context):
    records = event.get("Records", [])
    seen = []
    for rec in records:
        body = rec["body"]
        seen.append(body)
        print("EVID " + json.dumps({
            "body": body,
            "rc": rec.get("attributes", {}).get("ApproximateReceiveCount"),
            "msg_id": rec.get("messageId"),
        }, sort_keys=True))
    ret = {"seen": seen, "count": len(seen)}
    print("RET " + json.dumps(ret, sort_keys=True))
    return ret
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An SQS event source mapping delivers every one of N bodies to the handler (logged and
    returned, as a set, at-least-once) and the queue ends with zero visible and zero in flight.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
    """
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")

    src = _create_queue(ctx, VisibilityTimeout="60")
    fn = _create_lambda(
        ctx,
        _HANDLER,
        permissions=[{"Action": _POLL_ACTIONS, "Resource": src["arn"]}],
    )

    esm = _create_esm(
        ctx,
        EventSourceArn=src["arn"],
        FunctionName=fn["name"],
        BatchSize=_BATCH_SIZE,
        Enabled=True,
    )
    _wait_esm_state(ctx, esm["UUID"], "Enabled")

    since_ms = int(time.time() * 1000) - 5_000
    run_id = ctx.unique_name("payload-")
    sent = [f"{run_id}-{i:02d}" for i in range(_N)]
    for body in sent:
        sqs.send_message(QueueUrl=src["url"], MessageBody=body)

    def _all_bodies_seen(lines: list[str]) -> bool:
        return {r["body"] for r in _records(lines, "EVID ")} >= set(sent)

    evid_lines = _await_lines(ctx, fn["name"], since_ms, "EVID ", _all_bodies_seen, timeout_s=210.0)
    seen_bodies = [r["body"] for r in _records(evid_lines, "EVID ")]

    missing = sorted(set(sent) - set(seen_bodies))
    invented = sorted(set(seen_bodies) - set(sent))
    assert not missing, (
        f"the event source mapping never delivered {len(missing)} of {_N} messages to the handler: "
        f"missing={missing!r}; the handler logged {sorted(set(seen_bodies))!r}"
    )
    assert not invented, (
        f"the handler saw bodies that were never sent: {invented!r} (sent {sorted(sent)!r}) -- the "
        "poller substituted or duplicated content rather than forwarding the message body"
    )

    ret_lines = _await_lines(
        ctx,
        fn["name"],
        since_ms,
        "RET ",
        lambda ls: {b for r in _records(ls, "RET ") for b in r["seen"]} >= set(sent),
        timeout_s=90.0,
    )
    returns = _records(ret_lines, "RET ")
    assert len(returns) >= 1, (
        f"the handler logged {len(evid_lines)} per-record line(s) but never reached its return "
        "statement; an invocation that dies mid-batch is not a delivered batch"
    )
    returned = {b for r in returns for b in r["seen"]}
    assert returned == set(sent), (
        f"the RETURNED payloads cover {sorted(returned)!r}, but {_N} bodies {sorted(sent)!r} were "
        "sent -- the return value must account for exactly the messages that were delivered"
    )
    oversized = [r for r in returns if r["count"] > _BATCH_SIZE]
    assert not oversized, (
        f"an invocation received more records than BatchSize={_BATCH_SIZE}: {oversized!r}"
    )
    assert all(r["count"] == len(r["seen"]) for r in returns), (
        f"a returned payload's own count disagrees with its record list: {returns!r}"
    )

    visible, in_flight = _await_counts(ctx, src["url"], (0, 0), timeout_s=120.0)
    assert (visible, in_flight) == (0, 0), (
        f"the queue did not drain: ApproximateNumberOfMessages={visible}, "
        f"ApproximateNumberOfMessagesNotVisible={in_flight}. Zero visible alone is not a drain -- "
        "a poller that receives without deleting parks the messages in flight and they return."
    )

    rc_seen = {r["rc"] for r in _records(evid_lines, "EVID ")}
    assert None not in rc_seen, (
        "records arrived without attributes.ApproximateReceiveCount; the SQS event payload the "
        f"handler received was incomplete (receive counts observed: {sorted(map(str, rc_seen))!r})"
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
    """Poll the queue's depth until it reaches `want`, then return the last reading either way."""
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

    Keyed on (eventId, line) so repeated polls do not double-count but redeliveries still do."""
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
    """Delete /aws/lambda/<fn> in bounded rounds: a buffered flush can recreate it after a delete."""
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

    Teardown runs function delete, then the log-group reap, then the role."""
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

    # IAM role propagation has no observable condition, so retry the one error code it raises.
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
    """CreateEventSourceMapping, retried while it refuses the not-yet-propagated role's SQS grant."""
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
    """Wait until the ESM reports `want`; asserting delivery before that is a race."""
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_).get("State"),
        lambda s: s == want,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"ESM {uuid_} State={want}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
