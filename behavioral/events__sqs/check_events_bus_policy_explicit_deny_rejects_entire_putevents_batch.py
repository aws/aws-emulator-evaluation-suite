"""events-bus-policy-explicit-deny-rejects-entire-putevents-batch."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-bus-policy-explicit-deny-rejects-entire-putevents-batch"

GROUP = "permission"

SERVICES = ["events", "sqs"]


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An explicit Deny scoped by an events:source condition rejects the WHOLE mixed PutEvents batch
    with AccessDeniedException and delivers neither entry; removing the Deny restores both.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-perms.html
    """
    events = ctx.client("events")
    denied_source = _xname(ctx, "src-denied").replace("-", ".")
    allowed_source = _xname(ctx, "src-allowed").replace("-", ".")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    queue = _create_queue(ctx)
    rule = _put_rule_with_sqs_target(
        ctx, {"source": [denied_source, allowed_source]}, queue, bus=bus
    )

    # Prove the path live BEFORE breaking anything, so a later absence is suppression and not
    # warm-up: a fresh rule drops events until it goes live and EventBridge never retries a drop.
    _settle_delivery_path(ctx, bus, allowed_source, queue["url"], consecutive=2)
    _collect(ctx, queue["url"], window_s=2.0, max_total=100)

    events.put_permission(
        EventBusName=bus,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Sim2realDenyOneSource",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "events:PutEvents",
                        "Resource": bus_arn,
                        "Condition": {"StringEquals": {"events:source": denied_source}},
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _quiet(
            lambda: ctx.client("events").remove_permission(
                EventBusName=bus, RemoveAllPermissions=True
            )
        )
    )
    policy = events.describe_event_bus(Name=bus).get("Policy") or ""
    assert "Sim2realDenyOneSource" in policy, (
        f"PutPermission did not attach the Deny to bus {bus}: DescribeEventBus returned Policy="
        f"{policy!r}"
    )

    # Enforcement is eventually consistent (about 30 s on a warm bus), so poll to steady state.
    steady_code, steady_message = _poll_until_denied(events, bus, denied_source, timeout_s=180.0)
    assert steady_code == "AccessDeniedException", (
        f"a single denied-source PutEvents settled on error code {steady_code!r}, expected "
        f"'AccessDeniedException' -- an explicit Deny in a bus resource policy is a request-level "
        f"refusal, not a per-entry validation failure"
    )
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    refusal = (
        f"User: {caller_arn} is not authorized to perform: events:PutEvents on resource: "
        f"{bus_arn} with an explicit deny in a resource-based policy"
    )
    assert steady_message == refusal, f"unexpected refusal message: {steady_message!r}"
    _collect(ctx, queue["url"], window_s=2.0, max_total=100)

    denied_nonce = _xname(ctx, "n-denied")
    allowed_nonce = _xname(ctx, "n-allowed")
    mixed = [
        {
            "Source": denied_source,
            "DetailType": "MixedBatch",
            "Detail": json.dumps({"nonce": denied_nonce}),
            "EventBusName": bus,
        },
        {
            "Source": allowed_source,
            "DetailType": "MixedBatch",
            "Detail": json.dumps({"nonce": allowed_nonce}),
            "EventBusName": bus,
        },
    ]
    code, message = _error(lambda: events.put_events(Entries=list(mixed)))
    assert code == "AccessDeniedException", (
        f"a two-entry PutEvents carrying one denied source and one allowed source settled on "
        f"{code!r}, expected 'AccessDeniedException' for the whole request -- treating the "
        f"condition as a per-entry filter is the over-permissive reading real AWS does not implement"
    )
    assert message == refusal, f"unexpected mixed-batch refusal message: {message!r}"

    # Positive control, same file: the same allowed SOURCE on its own is accepted and really arrives.
    # It carries its own nonce, deliberately -- reusing the mixed batch's nonce would make the two
    # indistinguishable in the queue and the absence assertion below unfalsifiable.
    control_nonce = _xname(ctx, "n-control")
    control_sent = time.monotonic()
    control = events.put_events(
        Entries=[
            {
                "Source": allowed_source,
                "DetailType": "MixedBatch",
                "Detail": json.dumps({"nonce": control_nonce}),
                "EventBusName": bus,
            }
        ]
    )
    assert control.get("FailedEntryCount") == 0, (
        f"the positive control (the allowed entry on its own) was not accepted: {control!r} -- the "
        f"Deny is broader than the one source it names, so nothing below is attributable"
    )
    assert control["Entries"][0].get("EventId"), (
        f"the positive control returned no EventId: {control!r}"
    )
    got, others = _wait_for(
        ctx,
        queue["url"],
        lambda b: isinstance(b, dict) and b.get("detail", {}).get("nonce") == control_nonce,
        timeout_s=120.0,
    )
    control_latency_s = time.monotonic() - control_sent
    assert got, (
        f"the positive control's event {control_nonce!r} never reached {queue['name']}, so the "
        f"absences below cannot be distinguished from a dead delivery path (other messages seen: "
        f"{[_body(m) for m in others]!r})"
    )

    # The control has arrived, so the mixed batch -- issued earlier -- has had strictly longer to
    # arrive. Anything from it within a further 3x the control's latency would be delivery, not lag.
    absence_s = max(5.0, 3.0 * control_latency_s)
    leaked = [_body(m) for m in others] + [
        _body(m) for m in _collect(ctx, queue["url"], window_s=absence_s, max_total=100)
    ]
    leaked_nonces = sorted(
        b["detail"]["nonce"]
        for b in leaked
        if isinstance(b, dict)
        and isinstance(b.get("detail"), dict)
        and b["detail"].get("nonce") in (denied_nonce, allowed_nonce)
    )
    assert leaked_nonces == [], (
        f"the refused batch still delivered {leaked_nonces!r} to {queue['name']} after the positive "
        f"control had already arrived. A request that raised AccessDeniedException must publish "
        f"NEITHER entry -- not even the entry whose source the Deny does not name"
    )

    still = events.describe_event_bus(Name=bus).get("Policy") or ""
    assert "Sim2realDenyOneSource" in still, (
        f"the Deny statement vanished from bus {bus} during the check, so the refusal above was not "
        f"measured against a stable policy: DescribeEventBus now returns Policy={still!r}"
    )

    # Remove only the Deny statement; the same two-entry shape must now succeed with BOTH entries.
    events.remove_permission(EventBusName=bus, StatementId="Sim2realDenyOneSource")
    restored_nonce_denied = _xname(ctx, "n-restored-denied")
    restored_nonce_allowed = _xname(ctx, "n-restored-allowed")
    restored_batch = [
        {
            "Source": denied_source,
            "DetailType": "MixedBatch",
            "Detail": json.dumps({"nonce": restored_nonce_denied}),
            "EventBusName": bus,
        },
        {
            "Source": allowed_source,
            "DetailType": "MixedBatch",
            "Detail": json.dumps({"nonce": restored_nonce_allowed}),
            "EventBusName": bus,
        },
    ]
    restored = _put_until_accepted(events, restored_batch, timeout_s=180.0)
    assert restored.get("FailedEntryCount") == 0, (
        f"after removing the Deny statement, the identical two-entry batch shape (formerly-denied "
        f"source + allowed source) still did not fully succeed: {restored!r} -- removing a "
        f"request-level Deny must restore the whole request, not just the entry it never named"
    )

    restored_leaked_nonces = {restored_nonce_denied, restored_nonce_allowed}
    seen_restored: set[str] = set()

    def _restored_seen(body) -> bool:
        if isinstance(body, dict) and isinstance(body.get("detail"), dict):
            nonce = body["detail"].get("nonce")
            if nonce in restored_leaked_nonces:
                seen_restored.add(nonce)
        return seen_restored == restored_leaked_nonces

    _wait_for(ctx, queue["url"], _restored_seen, timeout_s=60.0)
    assert seen_restored == restored_leaked_nonces, (
        f"after removing the Deny, only {sorted(seen_restored)!r} of the restored batch's nonces "
        f"{sorted(restored_leaked_nonces)!r} reached {queue['name']!r} -- a request that is fully "
        f"accepted (FailedEntryCount == 0) must deliver every entry, not a subset"
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


def _quiet(fn) -> None:
    """Teardown helper: a delete that races another delete must not mask a verdict."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
            "ResourceNotFoundException",
        ):
            raise


def _error(fn) -> tuple[str, str]:
    """Return (error code, message) for a call that fails, and RAISE if it unexpectedly succeeds:
    an emulator accepting input real AWS refuses must not read like a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused but it SUCCEEDED and returned {resp!r}")


def _poll_until_denied(events, bus: str, source: str, *, timeout_s: float) -> tuple[str, str]:
    """PutEvents one entry on `source` until the call is refused; return its (code, message).

    A bus resource policy is eventually consistent: a Deny on a warm bus can take ~30 s to engage."""
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        try:
            last = events.put_events(
                Entries=[
                    {
                        "Source": source,
                        "DetailType": "DenyProbe",
                        "Detail": json.dumps({"nonce": "steady-state-probe"}),
                        "EventBusName": bus,
                    }
                ]
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code", ""), err.get("Message", "")
        time.sleep(2.0)
    raise AssertionError(
        f"the explicit Deny on bus {bus} for source {source!r} never took effect within "
        f"{timeout_s}s -- PutEvents was still accepted, last response {last!r}. The policy is "
        f"stored (DescribeEventBus returns it) but not enforced, which is the over-permissive "
        f"failure this check exists to catch"
    )


def _put_until_accepted(events, entries: list[dict], *, timeout_s: float) -> dict:
    """PutEvents `entries` until fully accepted (FailedEntryCount == 0); return that response.
    Removing a Deny is eventually consistent like adding one; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            last = events.put_events(Entries=list(entries))
            last_code = None
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            last = None
        else:
            if last.get("FailedEntryCount") == 0:
                return last
        time.sleep(2.0)
    raise AssertionError(
        f"the batch was never fully accepted within {timeout_s}s after removing the Deny -- "
        f"last error code={last_code!r} last response={last!r}"
    )


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
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10, keep=False):
    """Drain a queue over a bounded window with long-polling ReceiveMessage(MaxNumberOfMessages=10)
    and return EVERY message seen. Never raises and never swallows an assertion.

    An empty return is only meaningful once a positive control has already been observed."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            if not keep:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives, returning at once.
    Returns (matched, others) -- every non-matching message seen along the way is returned too so
    the caller can assert on leakage instead of silently discarding it."""
    sqs = ctx.client("sqs")
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _settle_delivery_path(ctx, bus: str, source: str, queue_url: str, *, consecutive: int = 2) -> None:
    """Emit single control events until `consecutive` of them round-trip back to back.

    A rule and its target become effective progressively and a dropped event is never retried,
    so one arrival proves only that SOME path is live."""
    events = ctx.client("events")
    streak = 0
    for _ in range(30):
        nonce = _xname(ctx, "warm")
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Warmup",
                    "Detail": json.dumps({"nonce": nonce}),
                    "EventBusName": bus,
                }
            ]
        )
        got, _ = _wait_for(
            ctx,
            queue_url,
            lambda b, n=nonce: isinstance(b, dict) and b.get("detail", {}).get("nonce") == n,
            timeout_s=15.0,
        )
        streak = streak + 1 if got else 0
        if streak >= consecutive:
            return
    raise AssertionError(
        f"the rule -> {queue_url} delivery path never round-tripped {consecutive} consecutive "
        f"control events before the Deny was applied, so no absence measured afterwards would be "
        f"attributable to the Deny (longest streak reached: {streak})"
    )


def _allow_service_send(queue_arn: str, service: str, source_arn: str) -> dict:
    """A queue policy granting one AWS service SendMessage on this queue, scoped by SourceArn."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowServiceSend",
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _put_rule_with_sqs_target(ctx, pattern: dict, queue: dict, *, bus: str) -> str:
    """Create an EventBridge rule for `pattern` on `bus`, grant the rule SendMessage on `queue`, and
    attach the queue as target t1. Registers remove_targets + delete_rule teardown (reverse order of
    creation). Returns the rule name."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern)
    )["RuleArn"]
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=name, EventBusName=bus, Force=True)
    )
    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn),
    )
    events.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=name, EventBusName=bus, Ids=["t1"], Force=True
        )
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
