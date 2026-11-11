"""eventbridge-rule-sends-to-sqs-target."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-sends-to-sqs-target"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge rule with an SQS target delivers matching events to the queue."""
    queue = _create_queue(ctx)
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    rule_name = ctx.unique_name("rule-eb-sqs-")
    # A per-run source keeps the rule hermetic on the shared default bus.
    source = ctx.unique_name("custom.ebsqs.")
    rule = events.put_rule(
        Name=rule_name, EventPattern=json.dumps({"source": [source]}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        _tolerant(
            lambda: ctx.client("events").delete_rule(Name=rule_name),
            "ResourceNotFoundException",
        )
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule["RuleArn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )

    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        _tolerant(
            lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"]),
            "ResourceNotFoundException",
        )
    )

    # A decoy that the pattern does not match goes out on the same bus first, in the same PutEvents.
    decoy_source = f"{source}.other"
    decoy = {
        "Source": decoy_source,
        "DetailType": "Test",
        "Detail": json.dumps({"order": "decoy"}),
    }
    messages, delivered_s = _reemit_until_delivered(
        ctx,
        queue["url"],
        {
            "Source": source,
            "DetailType": "Test",
            "Detail": json.dumps({"order": "abc"}),
        },
        before=decoy,
    )
    # Absence is bounded by the control: listen again for as long as the matching event took.
    messages += _collect_messages(
        ctx, queue["url"], expected_count=10, timeout_s=max(2.0, delivered_s)
    )
    bodies = [m["body"] for m in messages if isinstance(m["body"], dict)]
    decoys = [b for b in bodies if b.get("source") == decoy_source]
    assert not decoys, (
        f"the rule forwarded {len(decoys)} event(s) whose source its pattern does not match"
    )
    matched = [b for b in bodies if b.get("source") == source]
    assert matched, f"no delivered event carries source {source!r}: {bodies!r}"
    body = matched[0]
    assert body["detail"]["order"] == "abc", (
        f"expected delivered event detail.order == 'abc', got {body['detail']!r}"
    )
    for field, want in (
        ("source", source),
        ("detail-type", "Test"),
        ("account", ctx.account),
        ("region", ctx.region),
    ):
        assert body.get(field) == want, (
            f"expected delivered event {field}={want!r}, got {body.get(field)!r}"
        )
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_rule(ctx, rule_name, ["t1"])
    _gone_queue(ctx, queue["name"], queue["url"])


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _collect_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive or timeout_s passes; return what arrived."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return messages


def _reemit_until_delivered(ctx, queue_url, entry, *, attempts=8, poll_s=6.0, before=None):
    """Emit an EventBridge event repeatedly until it lands on the SQS queue; return the messages list.
    A freshly-created rule/target can silently drop the first PutEvents before the path is live, and
    EventBridge never retries a dropped event, so re-emitting is more reliable than one longer wait.
    ``before`` is emitted ahead of ``entry`` in the same PutEvents. Returns (messages, seconds the
    delivering attempt took). Raises AssertionError if never delivered."""
    events = ctx.client("events")
    for _ in range(attempts):
        sent = time.monotonic()
        events.put_events(Entries=[before, entry] if before else [entry])
        messages = _collect_messages(ctx, queue_url, expected_count=1, timeout_s=poll_s)
        if messages:
            return messages, time.monotonic() - sent
    raise AssertionError(
        f"event never delivered to {queue_url} after {attempts} attempts of {poll_s}s each"
    )


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, exactly the message ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message: expected {message!r}, got {msg!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_GONE = "The specified queue does not exist."


def _gone_rule(ctx, name: str, target_ids: list[str], bus: str = "default") -> None:
    ev = ctx.client("events")
    if target_ids:
        ev.remove_targets(Rule=name, EventBusName=bus, Ids=target_ids)
    ev.delete_rule(Name=name, EventBusName=bus)
    nf = ("ResourceNotFoundException",)
    gone = f"Rule {name} does not exist on EventBus {bus}."
    _poll_refused(lambda: ev.describe_rule(Name=name, EventBusName=bus), nf, 400, f"DescribeRule {name}", gone)
    listed = {r["Name"] for r in ev.list_rules(NamePrefix=name, EventBusName=bus).get("Rules", [])}
    assert name not in listed, f"ListRules still lists deleted rule {name}"
    _refused(
        lambda: ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "gone", "Arn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:gone"}]),
        nf, 400, f"PutTargets {name}", gone,
    )


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_GONE)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", _SQS_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
