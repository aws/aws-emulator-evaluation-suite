"""xsvc-logs-1-log-group-without-events-policy-not-delivered-and-counts-failed-invocations."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-logs-1-log-group-without-events-policy-not-delivered-and-counts-failed-invocations"
GROUP = "permission-chain"
SERVICES = ["events", "logs"]

_SOURCE = "custom.simparity"
_DETAIL_TYPE = "OrderPlaced"


# timing:real-time — metric: 18 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A rule whose log group does not admit events.amazonaws.com writes nothing and counts
    FailedInvocations, while a sibling rule's granted group receives every event; granting the
    policy makes the first group receive."""
    since = datetime.now(timezone.utc) - timedelta(minutes=2)
    no_retry = {"RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}
    pattern = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}

    bus, _ = _create_bus(ctx)
    ok_group, ok_arn = _create_group(ctx)
    bad_group, bad_arn = _create_group(ctx)

    ok_rule, ok_rule_arn = _create_rule(ctx, bus, pattern)
    _grant_events(ctx, ok_arn, ok_rule_arn)
    _add_target(ctx, bus, ok_rule, ok_arn, **no_retry)

    bad_rule, bad_rule_arn = _create_rule(ctx, bus, pattern)
    # Deliberately NO resource policy on bad_group: that is the one broken thing.
    _add_target(ctx, bus, bad_rule, bad_arn, **no_retry)
    # The group's teardown must also drop the policy the repair step adds below.
    ctx.on_cleanup(lambda: _delete_scoped_policies(ctx.client("logs"), bad_arn))

    def entry(tag: str) -> dict:
        return {
            "Source": _SOURCE,
            "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"id": f"{tag}-{uuid.uuid4().hex[:8]}", "phase": tag}),
            "EventBusName": bus,
        }

    _emit_until(ctx, [entry("ctl")], lambda: _log_events(ctx, ok_group))
    for i in range(3):
        before = len(_log_events(ctx, ok_group))
        _emit_until(ctx, [entry(f"ctl{i}")], lambda b=before: len(_log_events(ctx, ok_group)) > b)

    leaked = _log_events(ctx, bad_group)
    assert leaked == [], (
        f"group {bad_group} has no policy admitting events.amazonaws.com yet received "
        f"{len(leaked)} record(s): {[r['message'] for r in leaked]!r}"
    )
    streams = ctx.client("logs").describe_log_streams(logGroupName=bad_group)["logStreams"]
    assert streams == [], (
        f"EventBridge created log streams in the ungranted group: {[s['logStreamName'] for s in streams]!r}"
    )

    failed = _poll_until(
        lambda: _metric_sum(ctx, "FailedInvocations", bus, bad_rule, since),
        lambda v: v >= 1,
        timeout_s=240.0,
        interval_s=10.0,
        description=f"AWS/Events FailedInvocations >= 1 for rule {bad_rule}",
    )
    assert failed >= 1, f"FailedInvocations for {bad_rule} is {failed!r}"
    invoked = _poll_until(
        lambda: _metric_sum(ctx, "Invocations", bus, ok_rule, since),
        lambda v: v >= 4,
        timeout_s=180.0,
        interval_s=10.0,
        description=f"control rule {ok_rule} delivered 4+ events; its Invocations metric >= 4",
    )
    assert invoked >= 4, f"Invocations for control rule {ok_rule} is {invoked!r}"

    # Repair: grant the broken group exactly what the control group has, and it must now receive.
    _put_events_policy(ctx.client("logs"), bad_arn, bad_rule_arn)
    repaired, _ = _emit_until(
        ctx, [entry("fixed")], lambda: _log_events(ctx, bad_group), attempts=10
    )
    phases = [json.loads(r["message"]).get("detail", {}).get("phase") for r in repaired]
    assert phases and all(p == "fixed" for p in phases), (
        f"after the grant the group must hold only post-repair events; phases seen {phases!r}"
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
