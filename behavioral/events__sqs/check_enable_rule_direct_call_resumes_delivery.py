"""enable-rule-direct-call-resumes-delivery."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "enable-rule-direct-call-resumes-delivery"

GROUP = "event-propagation"

SERVICES = ["events", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A DISABLED rule delivers nothing and resumes delivery after a direct EnableRule call; an
    always-ENABLED control rule on the same pattern proves the bus stayed live throughout.
    """
    events = ctx.client("events")
    source = _xname(ctx, "src")
    pattern = {"source": [source]}
    ctl_q = _create_queue(ctx)
    subject_q = _create_queue(ctx)

    _put_rule_with_sqs_target(ctx, pattern, ctl_q)
    subject = _put_rule_with_sqs_target(ctx, pattern, subject_q)

    events.disable_rule(Name=subject)
    state = events.describe_rule(Name=subject)["State"]
    assert state == "DISABLED", f"DisableRule did not take effect: rule {subject} State={state!r}"

    def entry(marker: str) -> dict[str, str]:
        return {"Source": source, "DetailType": "Sim2realEnableRule", "Detail": json.dumps({"marker": marker})}

    ctl, _ = _emit_until(
        ctx,
        [entry("while-disabled")],
        ctl_q["url"],
        lambda b: isinstance(b, dict) and b.get("detail", {}).get("marker") == "while-disabled",
    )
    assert ctl, "the control rule (always ENABLED) never delivered; the negative below would prove nothing"
    leaked = _collect(ctx, subject_q["url"], window_s=20.0)
    assert leaked == [], (
        f"the DISABLED subject rule delivered {len(leaked)} message(s) while disabled, after the "
        f"control had already arrived on the same pattern: {leaked!r}"
    )

    # The direct call under test -- not a PutRule update.
    events.enable_rule(Name=subject)
    state = events.describe_rule(Name=subject)["State"]
    assert state == "ENABLED", f"EnableRule did not take effect: rule {subject} State={state!r}"

    resumed, _ = _emit_until(
        ctx,
        [entry("after-enable-rule")],
        subject_q["url"],
        lambda b: isinstance(b, dict) and b.get("detail", {}).get("marker") == "after-enable-rule",
    )
    assert resumed, "the subject rule never delivered after the direct EnableRule call"
    assert resumed[0].get("source") == source and resumed[0].get("detail-type") == "Sim2realEnableRule", (
        f"the resumed delivery's envelope was wrong: {resumed[0]!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    resp = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10):
    sqs = ctx.client("sqs")
    seen: list[Any] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(_body(msg))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _allow_service_send(queue_arn: str, service: str, source_arn: str) -> dict:
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
    ctx.client("sqs").set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _put_rule_with_sqs_target(ctx, pattern: dict, queue: dict) -> str:
    """Create an EventBridge rule for `pattern`, grant it SendMessage on `queue`, attach it as
    target t1. Registers remove_targets + delete_rule teardown. Returns the rule name."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    rule_arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern))["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=name, Force=True))
    _set_queue_policy(ctx, queue["url"], _allow_service_send(queue["arn"], "events.amazonaws.com", rule_arn))
    events.put_targets(Rule=name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: ctx.client("events").remove_targets(Rule=name, Ids=["t1"], Force=True))
    return name


def _emit_until(ctx, entries, queue_url, predicate, *, attempts=10, poll_s=8.0):
    events = ctx.client("events")
    others: list[Any] = []
    for _ in range(attempts):
        events.put_events(Entries=list(entries))
        deadline = time.monotonic() + poll_s
        matched = []
        while time.monotonic() < deadline:
            for body in _collect(ctx, queue_url, window_s=min(8.0, poll_s)):
                (matched if predicate(body) else others).append(body)
        if matched:
            return matched, others
    raise AssertionError(
        f"control event never delivered to {queue_url} after {attempts} PutEvents attempts "
        f"(non-matching messages seen meanwhile: {len(others)})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
