"""events-test-event-pattern-verdicts-agree-with-real-delivery."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "events-test-event-pattern-verdicts-agree-with-real-delivery"

GROUP = "event-propagation"

SERVICES = ["events", "sqs"]

# (row id, the matcher fragment merged into the rule's EventPattern, the event's detail,
#  the verdict real AWS gives)
_ROWS: list[tuple[str, dict, dict, bool]] = [
    ("numeric-in-range", {"detail": {"n": [{"numeric": [">", 10, "<", 20]}]}}, {"n": 15}, True),
    ("numeric-out-of-range", {"detail": {"n": [{"numeric": [">", 10, "<", 20]}]}}, {"n": 25}, False),
    ("prefix-match", {"detail": {"k": [{"prefix": "ab"}]}}, {"k": "abcdef"}, True),
    ("prefix-miss", {"detail": {"k": [{"prefix": "ab"}]}}, {"k": "zbcdef"}, False),
    ("exists-present", {"detail": {"opt": [{"exists": True}]}}, {"opt": "x"}, True),
    ("exists-absent", {"detail": {"opt": [{"exists": True}]}}, {"other": "x"}, False),
    ("anything-but-other-value", {"detail": {"k": [{"anything-but": ["no"]}]}}, {"k": "yes"}, True),
    ("anything-but-excluded-value", {"detail": {"k": [{"anything-but": ["no"]}]}}, {"k": "no"}, False),
    ("case-sensitive-differing-case", {"detail": {"k": ["Abc"]}}, {"k": "abc"}, False),
    ("cross-key-and-both-present", {"detail": {"a": ["1"], "b": ["2"]}}, {"a": "1", "b": "2"}, True),
]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """For ten pattern/event pairs, five expected true and five false, TestEventPattern's verdict
    matches the expectation and a rule with the same pattern delivers exactly the events it says
    match."""
    events = ctx.client("events")
    source = _xname(ctx, "src").replace("-", ".")

    verdicts: dict[str, bool] = {}
    for row, matcher, detail, _ in _ROWS:
        pattern = _rule_pattern(source, row, matcher)
        event = {
            "version": "0",
            "id": "00000000-0000-0000-0000-000000000000",
            "detail-type": _detail_type(row),
            "source": source,
            "account": "123456789012",
            "time": "2026-01-01T00:00:00Z",
            "region": ctx.region,
            "resources": [],
            "detail": detail,
        }
        verdicts[row] = events.test_event_pattern(
            EventPattern=json.dumps(pattern), Event=json.dumps(event)
        )["Result"]

    expected = {row: want for row, _, _, want in _ROWS}
    tep_disagree = {r: (verdicts[r], expected[r]) for r in expected if verdicts[r] != expected[r]}
    assert tep_disagree == {}, (
        f"TestEventPattern disagreed with the verdicts real AWS returns for these rows "
        f"(row -> (observed, expected)): {tep_disagree!r}"
    )

    # One control rule matching the source alone, so it receives EVERY row's event whatever its
    # matcher does. Its arrival is the barrier that licenses each False row's absence assertion.
    control_q = _create_queue(ctx)
    _put_rule_with_sqs_target(ctx, {"source": [source]}, control_q)

    row_queues: dict[str, dict[str, str]] = {}
    for row, matcher, _, _ in _ROWS:
        q = _create_queue(ctx)
        row_queues[row] = q
        _put_rule_with_sqs_target(ctx, _rule_pattern(source, row, matcher), q)

    entries = [
        {
            "Source": source,
            "DetailType": _detail_type(row),
            "Detail": json.dumps(dict(detail, row=row)),
        }
        for row, _, detail, _ in _ROWS
    ]

    # Every row rides on EVERY attempt, and both the control queue and all eleven row queues are
    # drained on every attempt. Two barriers have to be satisfied before any absence is asserted:
    # the control rule must have received all ten rows, and every row the engine is expected to
    # match must have received its own event at least once.
    #
    # Both are needed: each of the eleven rules goes live independently and a freshly created rule
    # silently drops events, so the control rule being live says nothing about any row rule.
    control_seen: set[str] = set()
    seen_per_row: dict[str, set[str]] = {row: set() for row in expected}
    wanted = {row for row, want in expected.items() if want}
    for _ in range(20):
        events.put_events(Entries=list(entries))
        for msg in _collect(ctx, control_q["url"], window_s=8.0, max_total=200):
            body = _body(msg)
            if isinstance(body, dict) and isinstance(body.get("detail"), dict):
                got = body["detail"].get("row")
                if got in expected:
                    control_seen.add(got)
        for row, q in row_queues.items():
            for msg in _collect(ctx, q["url"], window_s=3.0, max_total=200):
                body = _body(msg)
                if isinstance(body, dict) and isinstance(body.get("detail"), dict):
                    got = body["detail"].get("row")
                    if got is not None:
                        seen_per_row[row].add(got)
        if control_seen == set(expected) and wanted <= {
            row for row, seen in seen_per_row.items() if row in seen
        }:
            break

    assert control_seen == set(expected), (
        f"the control rule (pattern {{'source': [{source!r}]}}) never received every row, so no "
        f"absence below is provable: missing {sorted(set(expected) - control_seen)!r}"
    )
    delivered = {row: row in seen for row, seen in seen_per_row.items()}
    never_warmed = sorted(row for row in wanted if not delivered[row])
    assert never_warmed == [], (
        f"rows {never_warmed!r} are expected to match and never received their own event, so the "
        f"absences on the non-matching rows are not attributable to the matcher -- these rules never "
        f"went live. Per-row messages seen: "
        f"{ {r: sorted(s) for r, s in seen_per_row.items()} !r}"
    )

    misrouted = {
        row: sorted(r for r in seen if r != row)
        for row, seen in seen_per_row.items()
        if any(r != row for r in seen)
    }
    assert misrouted == {}, (
        f"a row's rule received an event intended for a different row, so the per-row delivery "
        f"verdicts are not attributable: {misrouted!r}"
    )

    delivery_disagree = {
        r: {"expected": expected[r], "delivered": delivered[r]}
        for r in expected
        if delivered[r] != expected[r]
    }
    assert delivery_disagree == {}, (
        f"real delivery disagreed with the verdict real AWS returns for these rows: "
        f"{delivery_disagree!r}"
    )

    both = {
        r: {"test_event_pattern": verdicts[r], "delivered": delivered[r]}
        for r in expected
        if verdicts[r] != delivered[r]
    }
    assert both == {}, (
        f"TestEventPattern and real delivery disagree on {len(both)} of {len(expected)} rows -- the "
        f"synchronous matcher and the delivery path are not the same engine: {both!r}"
    )
    assert sum(expected.values()) == 5 and len(expected) == 10, (
        f"the table must keep both directions represented, got {sum(expected.values())} True of "
        f"{len(expected)} rows: {expected!r}"
    )


def _detail_type(row: str) -> str:
    return f"row-{row}"


def _rule_pattern(source: str, row: str, matcher: dict) -> dict:
    """The row's matcher, scoped to this check's own source and the row's own detail-type."""
    return {"source": [source], "detail-type": [_detail_type(row)], **matcher}


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

    An empty return is only meaningful once the control barrier has already been observed -- that is
    what proves enough wall-clock and enough propagation elapsed for a delivery to have happened if
    the engine were going to make one."""
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


def _put_rule_with_sqs_target(ctx, pattern: dict, queue: dict) -> str:
    """Create an EventBridge rule for `pattern`, grant the rule SendMessage on `queue`, and attach
    the queue as target t1. Registers remove_targets + delete_rule teardown (reverse order of
    creation). Returns the rule name."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    rule_arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern))["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=name, Force=True))
    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn),
    )
    events.put_targets(Rule=name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=name, Ids=["t1"], Force=True)
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
