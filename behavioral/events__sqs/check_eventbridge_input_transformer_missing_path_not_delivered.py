"""eventbridge-input-transformer-missing-path-not-delivered."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-input-transformer-missing-path-not-delivered"

GROUP = "event-propagation"

SERVICES = ["events", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An InputTransformer whose input path is absent from the event delivers the template with the
    EMPTY STRING substituted for the unresolvable placeholder, never the raw, untransformed event,
    for a missing leaf and a missing intermediate object alike."""
    events = ctx.client("events")
    source = _xname(ctx, "src")
    q = _create_queue(ctx)
    paths_map = {"who": "$.detail.who", "deep": "$.detail.user.name"}
    template = '{"who": <who>, "deep": <deep>, "seen": "transformed"}'
    _put_rule_with_sqs_target(
        ctx,
        {"source": [source]},
        q,
        target={
            "InputTransformer": {
                "InputPathsMap": dict(paths_map),
                "InputTemplate": template,
            }
        },
    )

    # Unresolvable-path event: matches the rule pattern, but neither $.detail.who (missing leaf)
    # nor $.detail.user.name (missing intermediate object) can be resolved from it.
    unresolvable = {
        "Source": source,
        "DetailType": "TransformProbe",
        "Detail": json.dumps({"other": "no-who-field"}),
    }
    control = {
        "Source": source,
        "DetailType": "TransformProbe",
        "Detail": json.dumps({"who": "alice", "user": {"name": "bob"}}),
    }
    control_body = {"who": "alice", "deep": "bob", "seen": "transformed"}
    substituted_body = {"who": "", "deep": "", "seen": "transformed"}

    # The control is emitted FIRST and on its own, so the rule is proven live before the
    # unresolvable event is measured against it: a brand-new rule silently drops events until the
    # target path goes live, and that drop window is indistinguishable from a transform failure.
    ctl, seen_during_control = _emit_until(
        ctx,
        [control],
        q["url"],
        lambda b: isinstance(b, dict) and b.get("who") == "alice",
    )
    assert len(ctl) >= 1, (
        "control: an event carrying both input paths must transform and be delivered"
    )
    assert _body(ctl[0]) == control_body, (
        f"transformed control body is wrong: {_body(ctl[0])}"
    )

    # The unresolvable-path event IS delivered on that same live rule, and its body is the
    # template with the empty string substituted -- not null, not the literal placeholder text.
    subbed, seen_during_sub = _emit_until(
        ctx,
        [unresolvable],
        q["url"],
        lambda b: isinstance(b, dict) and b.get("seen") == "transformed" and b.get("who") == "",
    )
    assert _body(subbed[0]) == substituted_body, (
        f"an unresolvable input path must be substituted with the empty string, both for a "
        f"missing leaf ($.detail.who) and for a missing intermediate object "
        f"($.detail.user.name); got {_body(subbed[0])}"
    )

    delivered = [_body(m) for m in ctl + seen_during_control + subbed + seen_during_sub]
    delivered += [_body(m) for m in _collect(ctx, q["url"], window_s=20.0)]

    # The NEGATIVE: the raw event is never what arrives. Every message on the queue is one of the
    # two transformed shapes, so there is no raw-event or envelope fallback hiding alongside.
    assert all(isinstance(b, dict) for b in delivered), (
        f"every delivery must be the JSON the template produced, got {delivered}"
    )
    for body in delivered:
        for envelope_key in ("detail", "detail-type", "source", "other"):
            assert envelope_key not in body, (
                f"the raw event must never be delivered when a path is unresolvable: "
                f"{envelope_key!r} appeared in {body}"
            )
    distinct = {json.dumps(b, sort_keys=True) for b in delivered}
    assert distinct == {
        json.dumps(control_body, sort_keys=True),
        json.dumps(substituted_body, sort_keys=True),
    }, (
        f"the queue must carry exactly the two transformed shapes and nothing else, got "
        f"{sorted(distinct)}"
    )

    # ---- configuration-time negative: an undeclared template placeholder IS refused ----
    neg_rule = _xname(ctx, "rule-undeclared")
    events.put_rule(
        Name=neg_rule, EventPattern=json.dumps({"source": [source + ".never"]})
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=neg_rule, Force=True))

    try:
        events.put_targets(
            Rule=neg_rule,
            Targets=[
                {
                    "Id": "t1",
                    "Arn": q["arn"],
                    "InputTransformer": {
                        "InputPathsMap": {"who": "$.detail.who"},
                        "InputTemplate": '{"who": <who>, "nope": <missing>}',
                    },
                }
            ],
        )
        raise AssertionError(
            "an InputTemplate placeholder that InputPathsMap does not declare must be refused"
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "ValidationException", (
            f"expected ValidationException for an undeclared placeholder, got "
            f"{err.get('Code')}: {err.get('Message')!r}"
        )
        assert (
            err.get("Message")
            == "InputTemplate for target t1 contains invalid placeholder missing."
        ), (
            f"the refusal must name the target and the offending placeholder, got "
            f"{err.get('Message')!r}"
        )
    # effect absent: the refused PutTargets attached nothing
    assert events.list_targets_by_rule(Rule=neg_rule).get("Targets", []) == [], (
        f"a refused PutTargets must attach no target: "
        f"{events.list_targets_by_rule(Rule=neg_rule).get('Targets')}"
    )

    # control: declaring that placeholder makes the identical target acceptable, so the refusal
    # was about the undeclared name and not about the target or the template's shape.
    ok = events.put_targets(
        Rule=neg_rule,
        Targets=[
            {
                "Id": "t1",
                "Arn": q["arn"],
                "InputTransformer": {
                    "InputPathsMap": {"who": "$.detail.who", "missing": "$.detail.absent"},
                    "InputTemplate": '{"who": <who>, "nope": <missing>}',
                },
            }
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=neg_rule, Ids=["t1"])
    )
    assert ok.get("FailedEntryCount") == 0, f"control PutTargets reported failures: {ok}"
    assert [t["Id"] for t in events.list_targets_by_rule(Rule=neg_rule)["Targets"]] == [
        "t1"
    ], events.list_targets_by_rule(Rule=neg_rule)["Targets"]

    # ... and the symmetry is one-way: a declared path the template never references is fine, so
    # the rule is "every placeholder must be declared", not "map and template must correspond".
    unused = events.put_targets(
        Rule=neg_rule,
        Targets=[
            {
                "Id": "t1",
                "Arn": q["arn"],
                "InputTransformer": {
                    "InputPathsMap": {"who": "$.detail.who", "unused": "$.detail.zzz"},
                    "InputTemplate": '{"who": <who>}',
                },
            }
        ],
    )
    assert unused.get("FailedEntryCount") == 0, (
        f"an InputPathsMap entry the template never uses must be accepted: {unused}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
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

    This is the NEGATIVE observable. An empty return is only meaningful once a positive control
    has already been observed elsewhere in the check -- that is what proves enough wall-clock and
    enough propagation elapsed for a delivery to have happened if the emulator were going to make
    one. Used alone it would pass against an emulator that delivers nothing at all."""
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
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.
    Returns (matched, others) -- every non-matching message seen along the way is returned too so
    the caller can assert on leakage instead of silently discarding it."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


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


def _put_rule_with_sqs_target(
    ctx,
    pattern: dict,
    queue: dict,
    *,
    bus: str | None = None,
    target: dict | None = None,
) -> str:
    """Create an EventBridge rule for `pattern`, grant the rule SendMessage on `queue`, and attach
    the queue as target t1. Registers remove_targets + delete_rule teardown (reverse order of
    creation). Returns the rule name."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    kwargs: dict[str, Any] = {"Name": name, "EventPattern": json.dumps(pattern)}
    if bus:
        kwargs["EventBusName"] = bus
    rule_arn = events.put_rule(**kwargs)["RuleArn"]
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(
            Name=name, **({"EventBusName": bus} if bus else {}), Force=True
        )
    )
    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn),
    )
    tgt: dict[str, Any] = {"Id": "t1", "Arn": queue["arn"]}
    if target:
        tgt.update(target)
    events.put_targets(
        Rule=name, Targets=[tgt], **({"EventBusName": bus} if bus else {})
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=name, Ids=["t1"], **({"EventBusName": bus} if bus else {})
        )
    )
    return name


def _emit_until(ctx, entries, queue_url, predicate, *, attempts=10, poll_s=8.0):
    """PutEvents ALL of `entries` together, repeatedly, until a message whose parsed body satisfies
    `predicate` lands on `queue_url`. Returns (matched, others).

    Emitting every leg on every attempt is what makes the negative sound: a freshly created
    rule/target silently drops events until the path goes live and EventBridge never retries a
    dropped event, so the control has to be re-emitted -- and if the non-matching legs ride along
    on each attempt then, by the time the control arrives, every non-matching event has had at
    least as long to arrive as the control did. Non-delivery is therefore suppression, not lag."""
    events = ctx.client("events")
    others: list[dict[str, Any]] = []
    for _ in range(attempts):
        events.put_events(Entries=list(entries))
        got, extra = _wait_for(ctx, queue_url, predicate, timeout_s=poll_s)
        others.extend(extra)
        if got:
            return got, others
    raise AssertionError(
        f"control event never delivered to {queue_url} after {attempts} PutEvents attempts "
        f"(non-matching messages seen meanwhile: {len(others)}) -- the positive leg of this "
        "negative-delivery check could not be established, so the negative is unprovable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
