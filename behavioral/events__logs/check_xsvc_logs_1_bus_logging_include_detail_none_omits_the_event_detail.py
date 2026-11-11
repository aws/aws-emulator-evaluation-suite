"""xsvc-logs-1-bus-logging-include-detail-none-omits-the-event-detail."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-logs-1-bus-logging-include-detail-none-omits-the-event-detail"
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
    """Of two INFO-logging buses given the same event, the IncludeDetail=FULL record carries the put
    event_detail, while the NONE record omits event_detail (and its content) but keeps the same
    source, detail_type, caller account and log level.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    detail = {"id": f"o-{uuid.uuid4().hex[:8]}", "card": "4111-xxxx", "qty": 1}

    sides: dict[str, dict[str, str]] = {}
    for mode in ("FULL", "NONE"):
        bus, bus_arn = _create_bus(ctx, LogConfig={"Level": "INFO", "IncludeDetail": mode})
        got = ctx.client("events").describe_event_bus(Name=bus).get("LogConfig")
        assert got == {"Level": "INFO", "IncludeDetail": mode}, f"bus {bus} LogConfig is {got!r}"
        group, group_arn = _create_group(ctx, prefix="/aws/vendedlogs/")
        _grant_delivery(ctx, group_arn, account)
        src = _delivery_source(ctx, bus_arn, "INFO_LOGS")
        _delivery(ctx, src["name"], group_arn)
        sides[mode] = {"bus": bus, "arn": bus_arn, "group": group}

    entries = [
        {"Source": _SOURCE, "DetailType": _DETAIL_TYPE, "Detail": json.dumps(detail),
         "EventBusName": sides[m]["bus"]}
        for m in ("FULL", "NONE")
    ]
    sent = {"FULL": set(), "NONE": set()}

    def records(mode: str) -> list[dict]:
        return [r for r in _bus_records(ctx, sides[mode]["group"])
                if r.get("message_type") == "EVENT_INGEST_SUCCESS"
                and r.get("event_id") in sent[mode]]

    events = ctx.client("events")
    done = False
    for _ in range(10):
        resp = events.put_events(Entries=entries)
        assert resp["FailedEntryCount"] == 0, f"PutEvents rejected: {resp['Entries']!r}"
        sent["FULL"].add(resp["Entries"][0]["EventId"])
        sent["NONE"].add(resp["Entries"][1]["EventId"])
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if records("FULL") and records("NONE"):
                done = True
                break
            time.sleep(3.0)
        if done:
            break
    assert done, (
        f"ingest records missing: FULL={len(records('FULL'))} NONE={len(records('NONE'))} "
        f"for EventIds {sent!r}"
    )

    full = records("FULL")[0]
    none = records("NONE")[0]
    fd, nd = full.get("details") or {}, none.get("details") or {}
    assert json.loads(fd.get("event_detail", "null")) == detail, (
        f"FULL record event_detail {fd.get('event_detail')!r} != put detail {detail!r}"
    )
    assert "event_detail" not in nd, (
        f"IncludeDetail=NONE record still carries event_detail: {nd.get('event_detail')!r}"
    )
    assert not any(detail["card"] in json.dumps(v) for v in nd.values()), (
        f"IncludeDetail=NONE leaked detail content into another field: {nd!r}"
    )
    for k, want in (("source", _SOURCE), ("detail_type", _DETAIL_TYPE),
                    ("caller_account_id", account)):
        assert nd.get(k) == want == fd.get(k), (
            f"details[{k!r}]: NONE={nd.get(k)!r} FULL={fd.get(k)!r}, expected {want!r} on both"
        )
    assert none.get("event_bus_name") == sides["NONE"]["bus"], (
        f"NONE record names bus {none.get('event_bus_name')!r}, expected {sides['NONE']['bus']!r}"
    )
    assert none.get("log_level") == "INFO" == full.get("log_level"), (
        f"log_level NONE={none.get('log_level')!r} FULL={full.get('log_level')!r}"
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

def _grant_delivery(ctx, group_arn: str, account: str) -> None:
    """Scoped (log-group) policy for the vended-logs delivery service; no account-level policy."""
    logs = ctx.client("logs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "delivery.logs.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"{group_arn}:log-stream:*",
            "Condition": {"StringEquals": {"aws:SourceAccount": account}},
        }],
    }
    logs.put_resource_policy(policyDocument=json.dumps(policy), resourceArn=group_arn)
    ctx.on_cleanup(lambda: _delete_scoped_policies(logs, group_arn))


def _delivery_source(ctx, bus_arn: str, log_type: str) -> dict:
    logs = ctx.client("logs")
    name = _xname(ctx, "src")
    out = logs.put_delivery_source(name=name, resourceArn=bus_arn, logType=log_type,
                                   tags=dict(_TAG))["deliverySource"]
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=name))
    return out


def _delivery(ctx, source_name: str, group_arn: str) -> dict:
    logs = ctx.client("logs")
    dname = _xname(ctx, "dst")
    dest = logs.put_delivery_destination(
        name=dname, deliveryDestinationConfiguration={"destinationResourceArn": group_arn},
        tags=dict(_TAG),
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dname))
    delivery = logs.create_delivery(deliverySourceName=source_name,
                                    deliveryDestinationArn=dest["arn"], tags=dict(_TAG))["delivery"]
    ctx.on_cleanup(lambda: logs.delete_delivery(id=delivery["id"]))
    return delivery


def _bus_records(ctx, group: str) -> list[dict]:
    """Every JSON bus-log record in the group (the delivery's validation line is not JSON)."""
    out = []
    for ev in _log_events(ctx, group):
        try:
            body = json.loads(ev["message"])
        except (TypeError, ValueError):
            continue
        if isinstance(body, dict):
            out.append(body)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
