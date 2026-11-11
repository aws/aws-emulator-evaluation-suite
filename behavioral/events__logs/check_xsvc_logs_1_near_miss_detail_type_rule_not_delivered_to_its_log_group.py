"""xsvc-logs-1-near-miss-detail-type-rule-not-delivered-to-its-log-group."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-logs-1-near-miss-detail-type-rule-not-delivered-to-its-log-group"
GROUP = "event-propagation"
SERVICES = ["events", "logs"]

_SOURCE = "custom.simparity"
_DETAIL_TYPE = "OrderPlaced"


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A rule on the near-miss detail-type OrderPlacedX writes nothing to its log group while the
    exact OrderPlaced rule delivers the same events; correcting the pattern makes the same group
    receive."""
    events = ctx.client("events")

    bus, _ = _create_bus(ctx)
    hit_group, hit_arn = _create_group(ctx)
    miss_group, miss_arn = _create_group(ctx)

    hit_rule, hit_rule_arn = _create_rule(
        ctx, bus, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}
    )
    _grant_events(ctx, hit_arn, hit_rule_arn)
    _add_target(ctx, bus, hit_rule, hit_arn)

    miss_rule, miss_rule_arn = _create_rule(
        ctx, bus, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE + "X"]}
    )
    _grant_events(ctx, miss_arn, miss_rule_arn)
    _add_target(ctx, bus, miss_rule, miss_arn)

    def entry(tag: str) -> dict:
        return {
            "Source": _SOURCE,
            "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"id": f"{tag}-{uuid.uuid4().hex[:8]}", "phase": tag}),
            "EventBusName": bus,
        }

    # Barrier: the exact-match group must receive, then keep receiving, while the near miss stays
    # empty. Every one of these events was offered to the near-miss rule at the same instant.
    _emit_until(ctx, [entry("ctl")], lambda: _log_events(ctx, hit_group))
    for i in range(3):
        before = len(_log_events(ctx, hit_group))
        _emit_until(ctx, [entry(f"ctl{i}")], lambda b=before: len(_log_events(ctx, hit_group)) > b)

    leaked = _log_events(ctx, miss_group)
    assert leaked == [], (
        f"rule {miss_rule} (detail-type {_DETAIL_TYPE + 'X'!r}) delivered {len(leaked)} record(s) "
        f"for {_DETAIL_TYPE!r} events: {[r['message'] for r in leaked]!r}"
    )
    hit_payloads = [json.loads(r["message"]) for r in _log_events(ctx, hit_group)]
    assert all(p.get("detail-type") == _DETAIL_TYPE for p in hit_payloads), (
        f"matching group holds a record with an unexpected detail-type: {hit_payloads!r}"
    )

    # Repair the one broken thing -- the pattern -- and the same group must now receive.
    events.put_rule(
        Name=miss_rule, EventBusName=bus,
        EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}),
    )
    repaired, _ = _emit_until(ctx, [entry("fixed")], lambda: _log_events(ctx, miss_group))
    bodies = [json.loads(r["message"]) for r in repaired]
    assert all(b.get("detail", {}).get("phase") == "fixed" for b in bodies), (
        f"after the pattern fix the group received events emitted BEFORE it: {bodies!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_TAG = {"sim2real": "xsvc-logs-1"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_bus(ctx, **kwargs) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")
    arn = events.create_event_bus(
        Name=name, Tags=[{"Key": k, "Value": v} for k, v in _TAG.items()], **kwargs
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=name))
    return name, arn


def _create_group(ctx, prefix: str = "") -> tuple[str, str]:
    """Create a log group and return (name, arn-without-the-trailing-:*)."""
    logs = ctx.client("logs")
    name = prefix + _xname(ctx, "lg")
    logs.create_log_group(logGroupName=name, tags=dict(_TAG))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    arn = None
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                arn = g["arn"]
    assert arn, f"DescribeLogGroups does not list the group just created: {name!r}"
    return name, arn[:-2] if arn.endswith(":*") else arn


def _delete_scoped_policies(logs, group_arn: str) -> None:
    for p in logs.describe_resource_policies(
        resourceArn=group_arn, policyScope="RESOURCE"
    ).get("resourcePolicies", []):
        logs.delete_resource_policy(resourceArn=group_arn, expectedRevisionId=p["revisionId"])


def _grant_events(ctx, group_arn: str, rule_arn: str) -> None:
    """A policy scoped to ONE log group (never an account-level one) letting ONE rule write to it."""
    logs = ctx.client("logs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"{group_arn}:*",
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    logs.put_resource_policy(policyDocument=json.dumps(policy), resourceArn=group_arn)
    ctx.on_cleanup(lambda: _delete_scoped_policies(logs, group_arn))


def _create_rule(ctx, bus: str, pattern: dict) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAG.items()],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=bus, Force=True))
    return name, arn


def _add_target(ctx, bus: str, rule: str, group_arn: str, tid: str = "t1", **extra) -> None:
    events = ctx.client("events")
    resp = events.put_targets(
        Rule=rule, EventBusName=bus, Targets=[{"Id": tid, "Arn": group_arn, **extra}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=[tid]))
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed: {resp.get('FailedEntries')!r}"


def _log_events(ctx, group: str) -> list[dict]:
    out: list[dict] = []
    for page in ctx.client("logs").get_paginator("filter_log_events").paginate(logGroupName=group):
        out.extend(page.get("events", []))
    return out


def _emit_until(ctx, entries, probe, *, attempts=8, poll_s=12.0):
    """PutEvents `entries` together, repeatedly, until probe() returns something truthy.

    A freshly created rule/target can drop events until the path is live and EventBridge does not
    replay a dropped event, so the event is re-emitted rather than waited on. Returns
    (probe result, [EventIds per attempt])."""
    events = ctx.client("events")
    sent: list[list[str]] = []
    for _ in range(attempts):
        resp = events.put_events(Entries=list(entries))
        assert resp["FailedEntryCount"] == 0, f"PutEvents rejected entries: {resp['Entries']!r}"
        sent.append([e["EventId"] for e in resp["Entries"]])
        deadline = time.monotonic() + poll_s
        while time.monotonic() < deadline:
            got = probe()
            if got:
                return got, sent
            time.sleep(2.0)
    raise AssertionError(f"nothing observed after {attempts} PutEvents attempts (sent {sent!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
