"""events-rate-schedule-fires-repeatedly-with-the-configured-period."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from behavioral_harness import tags

CHECK = "events-rate-schedule-fires-repeatedly-with-the-configured-period"

GROUP = "event-propagation"

SERVICES = ["events", "sqs"]

_PERIOD_S = 60.0


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A rate(1 minute) rule really fires as a CADENCE (consecutive deliveries about one period
    apart), and DisableRule really stops it: no delivery after two further scheduled slots."""
    events = ctx.client("events")
    queue = _create_queue(ctx)

    # Schedules are only permitted on the DEFAULT bus, so no bus is created here.
    rule = _xname(ctx, "sched")
    rule_arn = events.put_rule(
        Name=rule, ScheduleExpression="rate(1 minute)", State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule, Force=True))
    _set_queue_policy(
        ctx,
        queue["url"],
        _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn),
    )
    events.put_targets(Rule=rule, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule, Ids=["t1"], Force=True)
    )

    fired: list[dict[str, Any]] = []
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline and len(fired) < 3:
        for msg in _collect(ctx, queue["url"], window_s=15.0, max_total=50):
            body = _body(msg)
            if isinstance(body, dict) and rule_arn in (body.get("resources") or []):
                fired.append(body)
    assert len(fired) >= 3, (
        f"the rate(1 minute) rule {rule} delivered only {len(fired)} scheduled event(s) within 300 s, "
        f"so no cadence is observable: {fired!r}"
    )

    for env in fired:
        assert env.get("detail-type") == "Scheduled Event", (
            f"a scheduled delivery carried detail-type={env.get('detail-type')!r}, expected "
            f"'Scheduled Event': {env!r}"
        )
        assert env.get("detail") == {}, (
            f"a scheduled delivery carried a non-empty detail {env.get('detail')!r}; a scheduled "
            f"event has no payload: {env!r}"
        )
        assert env.get("resources") == [rule_arn], (
            f"a scheduled delivery named resources={env.get('resources')!r}, expected exactly "
            f"[{rule_arn!r}] -- the envelope must attribute the firing to the rule that caused it"
        )
        assert env.get("source") == "aws.events", (
            f"a scheduled delivery carried source={env.get('source')!r}, expected 'aws.events': "
            f"{env!r}"
        )

    stamps = [_epoch(env["time"]) for env in fired]
    times = [env["time"] for env in fired]
    assert stamps == sorted(stamps) and len(set(stamps)) == len(stamps), (
        f"the scheduled firings' envelope 'time' values are not strictly increasing: {times!r}"
    )
    gaps = [round(b - a, 1) for a, b in zip(stamps, stamps[1:])]
    bad = [g for g in gaps if not 0.5 * _PERIOD_S <= g <= 2.0 * _PERIOD_S]
    assert bad == [], (
        f"consecutive scheduled firings were {gaps!r} seconds apart; every gap must fall within "
        f"{0.5 * _PERIOD_S}-{2.0 * _PERIOD_S}s of the configured rate(1 minute). The band is wide on "
        f"purpose -- it compares two observed timestamps to each other, not to a latency budget -- so "
        f"{bad!r} means the rate expression is not driving the cadence at all. Observed times: "
        f"{times!r}"
    )

    events.disable_rule(Name=rule)
    state = events.describe_rule(Name=rule)["State"]
    assert state == "DISABLED", (
        f"DisableRule did not take effect: rule {rule} reports State={state!r}, expected 'DISABLED'"
    )
    # Drain whatever the scheduler had already handed to SQS before the disable landed.
    _collect(ctx, queue["url"], window_s=15.0, max_total=50)

    # Watch until two FURTHER scheduled slots, predicted from the last observed firing, have passed.
    # Deriving the window from the observed cadence is what makes the emptiness meaningful: at least
    # two deliveries were due in it, so zero is suppression and not a short window.
    watch_until_epoch = stamps[-1] + 2 * _PERIOD_S + 10.0
    late: list[dict[str, Any]] = []
    while time.time() < watch_until_epoch:
        for msg in _collect(ctx, queue["url"], window_s=15.0, max_total=50):
            body = _body(msg)
            if isinstance(body, dict) and rule_arn in (body.get("resources") or []):
                late.append(body)
    assert late == [], (
        f"the DISABLED rule {rule} kept firing: {len(late)} scheduled event(s) arrived in the window "
        f"ending at epoch {watch_until_epoch}, which covered two further scheduled slots after the "
        f"last firing observed while it was ENABLED ({times[-1]!r}). Late envelopes: "
        f"{[e.get('time') for e in late]!r}"
    )
    assert events.describe_rule(Name=rule)["State"] == "DISABLED", (
        f"rule {rule} did not stay DISABLED for the duration of the absence window"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _epoch(iso: str) -> float:
    """Parse an EventBridge envelope 'time' (RFC3339, always Z-suffixed) to epoch seconds.

    Parsed structurally rather than by string surgery so a change of offset form does not silently
    turn into a wrong gap."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


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

    Used as the NEGATIVE observable in the post-disable window: an empty return is meaningful only
    because the window is derived from firings already observed while the rule was ENABLED."""
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
    """A queue policy granting one AWS service SendMessage on this queue, scoped by SourceArn.

    The SourceArn condition is load-bearing here: the account may be shared and other checks also
    create schedule rules on the default bus, so without it another rule's firings could land on this
    queue and contaminate the cadence measurement."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
