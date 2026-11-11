"""xsvc-logs-1-input-template-without-timestamp-and-message-not-delivered-to-log-group."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-logs-1-input-template-without-timestamp-and-message-not-delivered-to-log-group"
GROUP = "event-propagation"
SERVICES = ["events", "logs"]

_SOURCE = "custom.simparity"
_DETAIL_TYPE = "OrderPlaced"
_GOOD = '{"timestamp": <t>, "message": "order <oid>"}'
_BAD = '{"order": <oid>, "kind": "plain"}'


# timing:real-time — metric: 34 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A log-group target whose InputTemplate is not timestamp/message JSON is accepted but never
    written and counted in FailedInvocations, while a correct target on the same rule receives;
    fixing the template delivers."""
    since = datetime.now(timezone.utc) - timedelta(minutes=2)
    no_retry = {"RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}
    paths = {"t": "$.time", "oid": "$.detail.id"}

    bus, _ = _create_bus(ctx)
    good_group, good_arn = _create_group(ctx)
    bad_group, bad_arn = _create_group(ctx)
    rule, rule_arn = _create_rule(ctx, bus, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})
    _grant_events(ctx, good_arn, rule_arn)
    _grant_events(ctx, bad_arn, rule_arn)
    _add_target(ctx, bus, rule, good_arn, tid="good",
                InputTransformer={"InputPathsMap": paths, "InputTemplate": _GOOD}, **no_retry)
    _add_target(ctx, bus, rule, bad_arn, tid="bad",
                InputTransformer={"InputPathsMap": paths, "InputTemplate": _BAD}, **no_retry)

    def entry(tag: str) -> dict:
        return {
            "Source": _SOURCE,
            "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"id": f"{tag}-{uuid.uuid4().hex[:8]}"}),
            "EventBusName": bus,
        }

    _emit_until(ctx, [entry("ctl")], lambda: _log_events(ctx, good_group))
    for i in range(3):
        before = len(_log_events(ctx, good_group))
        _emit_until(ctx, [entry(f"ctl{i}")], lambda b=before: len(_log_events(ctx, good_group)) > b)

    good = [r["message"] for r in _log_events(ctx, good_group)]
    assert good and all(m.startswith("order ctl") for m in good), (
        f"good-template group holds unexpected records: {good!r}"
    )
    leaked = _log_events(ctx, bad_group)
    assert leaked == [], (
        f"a template without timestamp/message was written to {bad_group}: "
        f"{[r['message'] for r in leaked]!r}"
    )
    failed = _poll_until(
        lambda: _metric_sum(ctx, "FailedInvocations", bus, rule, since),
        lambda v: v >= 1,
        timeout_s=240.0,
        interval_s=10.0,
        description=f"AWS/Events FailedInvocations >= 1 for rule {rule}",
    )
    assert failed >= 1, f"FailedInvocations for {rule} is {failed!r}"

    # Repair the one broken thing: give the bad target the good template.
    resp = ctx.client("events").put_targets(
        Rule=rule, EventBusName=bus,
        Targets=[{"Id": "bad", "Arn": bad_arn, **no_retry,
                  "InputTransformer": {"InputPathsMap": paths, "InputTemplate": _GOOD}}],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets (repair) failed: {resp.get('FailedEntries')!r}"
    repaired, _ = _emit_until(ctx, [entry("fixed")], lambda: _log_events(ctx, bad_group))
    msgs = [r["message"] for r in repaired]
    assert msgs and all(m.startswith("order fixed-") for m in msgs), (
        f"after the template fix the group must hold only rendered post-repair messages: {msgs!r}"
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
