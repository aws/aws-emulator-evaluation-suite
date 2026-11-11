"""xsvc-logs-1-input-transformer-renders-message-and-event-time-into-the-log-record."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-logs-1-input-transformer-renders-message-and-event-time-into-the-log-record"
GROUP = "event-propagation"
SERVICES = ["events", "logs"]

_SOURCE = "custom.simparity"
_DETAIL_TYPE = "OrderPlaced"
_TEMPLATE = '{"timestamp": <t>, "message": "order <oid> qty <qty> from <src> via <dt>"}'


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
    """An InputTransformer on a log-group target writes the exact rendered message, with the log
    event timestamp taken from the event's Time and ingestion time not before it."""
    bus, _ = _create_bus(ctx)
    group, group_arn = _create_group(ctx)
    rule, rule_arn = _create_rule(ctx, bus, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})
    _grant_events(ctx, group_arn, rule_arn)
    _add_target(
        ctx, bus, rule, group_arn,
        InputTransformer={
            "InputPathsMap": {
                "t": "$.time", "oid": "$.detail.id", "qty": "$.detail.qty",
                "src": "$.source", "dt": "$.detail-type",
            },
            "InputTemplate": _TEMPLATE,
        },
    )

    order_id = f"o-{uuid.uuid4().hex[:10]}"
    when = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=45)
    entry = {
        "Source": _SOURCE,
        "DetailType": _DETAIL_TYPE,
        "Detail": json.dumps({"id": order_id, "qty": 7, "noise": {"nested": True}}),
        "Time": when,
        "EventBusName": bus,
    }
    got, _ = _emit_until(ctx, [entry], lambda: _log_events(ctx, group))

    want_msg = f"order {order_id} qty 7 from {_SOURCE} via {_DETAIL_TYPE}"
    want_ts = int(when.timestamp() * 1000)
    for rec in got:
        assert rec["message"] == want_msg, (
            f"rendered message mismatch:\n got:      {rec['message']!r}\n expected: {want_msg!r}"
        )
        assert rec["timestamp"] == want_ts, (
            f"log event timestamp {rec['timestamp']!r} is not the event Time {want_ts!r} "
            f"({when.isoformat()}); the <timestamp> field must set it"
        )
        assert rec["ingestionTime"] >= rec["timestamp"], (
            f"ingestionTime {rec['ingestionTime']!r} precedes the event timestamp {rec['timestamp']!r}"
        )


_XSVC_PREFIX = "sim2real-xsvc-"
_TAG = {"sim2real": "xsvc-logs-1"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded wait that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _metric_sum(ctx, metric: str, bus: str, rule: str, since: datetime) -> float:
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": "EventBusName", "Value": bus}, {"Name": "RuleName", "Value": rule}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(p["Sum"] for p in resp["Datapoints"])


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


def _put_events_policy(logs, group_arn: str, rule_arn: str) -> None:
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


def _grant_events(ctx, group_arn: str, rule_arn: str) -> None:
    """A policy scoped to ONE log group (never an account-level one) letting ONE rule write to it."""
    logs = ctx.client("logs")
    _put_events_policy(logs, group_arn, rule_arn)
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
