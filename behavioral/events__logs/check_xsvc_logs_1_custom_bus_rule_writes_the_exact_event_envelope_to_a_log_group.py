"""xsvc-logs-1-custom-bus-rule-writes-the-exact-event-envelope-to-a-log-group."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-logs-1-custom-bus-rule-writes-the-exact-event-envelope-to-a-log-group"
GROUP = "event-propagation"
SERVICES = ["events", "logs"]

_SOURCE = "custom.simparity"
_DETAIL_TYPE = "OrderPlaced"


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
    """A custom-bus rule with a log-group target writes the event envelope verbatim as one log event
    whose id is the PutEvents EventId and whose timestamp is the event's Time."""
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bus, _ = _create_bus(ctx)
    group, group_arn = _create_group(ctx)
    rule, rule_arn = _create_rule(ctx, bus, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})
    _grant_events(ctx, group_arn, rule_arn)
    _add_target(ctx, bus, rule, group_arn)

    order_id = f"o-{uuid.uuid4().hex[:10]}"
    detail = {"id": order_id, "qty": 3, "items": ["sku-1", "sku-2"], "gift": False}
    resource = f"arn:aws:simparity:{ctx.region}:{account}:order/{order_id}"
    when = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=30)
    entry = {
        "Source": _SOURCE,
        "DetailType": _DETAIL_TYPE,
        "Detail": json.dumps(detail),
        "Resources": [resource],
        "Time": when,
        "EventBusName": bus,
    }

    got, sent_ids = _emit_until(ctx, [entry], lambda: _log_events(ctx, group))
    sent = {i for batch in sent_ids for i in batch}
    assert got, f"no log event ever reached {group}"

    for rec in got:
        try:
            body = json.loads(rec["message"])
        except (TypeError, ValueError):
            raise AssertionError(f"log message is not JSON: {rec['message']!r}") from None
        assert isinstance(body, dict), f"log message is not a JSON object: {body!r}"
        assert body.get("id") in sent, (
            f"record id {body.get('id')!r} is not any EventId PutEvents returned ({sorted(sent)!r})"
        )
        expected = {
            "version": "0",
            "id": body.get("id"),
            "detail-type": _DETAIL_TYPE,
            "source": _SOURCE,
            "account": account,
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "region": ctx.region,
            "resources": [resource],
            "detail": detail,
        }
        assert body == expected, (
            f"delivered envelope differs from the event that was put.\n got:      {body!r}\n"
            f" expected: {expected!r}"
        )
        want_ts = int(when.timestamp() * 1000)
        assert rec["timestamp"] == want_ts, (
            f"log event timestamp {rec['timestamp']!r} is not the event Time {want_ts!r} "
            f"({when.isoformat()})"
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
