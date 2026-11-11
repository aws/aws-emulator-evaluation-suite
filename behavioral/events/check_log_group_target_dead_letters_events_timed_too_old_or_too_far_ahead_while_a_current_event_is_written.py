"""log-group-target-dead-letters-events-timed-too-old-or-too-far-ahead-while-a-current-event-is-written."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "log-group-target-dead-letters-events-timed-too-old-or-too-far-ahead-while-a-current-event-is-written"
GROUP = "logs-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A log group target writes a current-time event stamped with its Time, but dead-letters events
    timed 15 days ago (INVALID_PARAMETER) or 3 hours ahead (EVENTS_IN_BATCH_REQUEST_REJECTED) from
    one batch.
    """
    events = ctx.client("events")
    logs = ctx.client("logs")
    group, group_arn = _create_group(ctx, logs)
    dlq_url, dlq_arn = _create_dlq(ctx)

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.logs.")
    rule, rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    _grant_events(ctx, logs, group_arn, rule_arn)
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{
        "Id": "group", "Arn": group_arn, "DeadLetterConfig": {"Arn": dlq_arn},
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    # Liveness: re-publish a current event until the group holds one.
    _publish_until_written(ctx, events, logs, bus, source, group)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    times = {"current": now, "old": now - timedelta(days=15), "future": now + timedelta(hours=3)}
    marker = ctx.unique_name("m-")
    resp = events.put_events(Entries=[
        {"EventBusName": bus, "Source": source, "DetailType": kind, "Time": when,
         "Detail": json.dumps({"m": marker})}
        for kind, when in times.items()])
    assert resp["FailedEntryCount"] == 0, f"PutEvents must accept all three entries: {resp['Entries']!r}"
    ids = {kind: e["EventId"] for kind, e in zip(times, resp["Entries"])}

    dead = _drain_until(ctx, dlq_url, lambda got: {m["body"].get("id") for m in got} >= {ids["old"], ids["future"]})
    by_id = {m["body"]["id"]: m for m in dead}
    old, future = by_id[ids["old"]], by_id[ids["future"]]
    want_msg = f"Could not complete putLogEvents call for {group}."
    assert old["attrs"] == {"ERROR_CODE": "INVALID_PARAMETER", "ERROR_MESSAGE": want_msg,
                            "RULE_ARN": rule_arn, "TARGET_ARN": group_arn}, (
        f"the 15-day-old event's dead letter carries {_shape(old['attrs'], rule_arn, group_arn)!r}"
    )
    assert future["attrs"] == {"ERROR_CODE": "EVENTS_IN_BATCH_REQUEST_REJECTED",
                               "ERROR_MESSAGE": want_msg,
                               "EXHAUSTED_RETRY_CONDITION": "MaximumRetryAttempts",
                               "RETRY_ATTEMPTS": "0", "RULE_ARN": rule_arn, "TARGET_ARN": group_arn}, (
        f"the future-timed event's dead letter carries {_shape(future['attrs'], rule_arn, group_arn)!r}"
    )
    assert ids["current"] not in by_id, "the current-time event was dead-lettered"

    written = _poll_written(logs, group, marker, want=lambda evs: ids["current"] in evs)
    assert set(written) == {ids["current"]}, (
        f"the group must hold exactly the current-time event of the batch; it holds "
        f"{sorted(k for k, v in ids.items() if v in written)!r}"
    )
    assert written[ids["current"]] == int(times["current"].timestamp() * 1000), (
        f"the written log event's timestamp {written[ids['current']]!r} is not the event Time"
    )


def _shape(attrs: dict, rule_arn: str, group_arn: str) -> dict:
    """The dead-letter attributes with the two ARNs replaced by whether they matched."""
    out = dict(attrs)
    if "RULE_ARN" in out:
        out["RULE_ARN"] = out["RULE_ARN"] == rule_arn
    if "TARGET_ARN" in out:
        out["TARGET_ARN"] = out["TARGET_ARN"] == group_arn
    return out


def _create_group(ctx, logs) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    arn = None
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        arn = next((g["arn"] for g in page["logGroups"] if g["logGroupName"] == name), arn)
    assert arn, "the created log group is not listed"
    return name, arn.removesuffix(":*")


def _grant_events(ctx, logs, group_arn: str, rule_arn: str) -> None:
    """A policy on ONE log group (never an account-level one) letting ONE rule write to it."""
    logs.put_resource_policy(resourceArn=group_arn, policyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"{group_arn}:*",
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}))

    def _revoke() -> None:
        for pol in logs.describe_resource_policies(
                resourceArn=group_arn, policyScope="RESOURCE").get("resourcePolicies", []):
            logs.delete_resource_policy(resourceArn=group_arn, expectedRevisionId=pol["revisionId"])

    ctx.on_cleanup(_revoke)


def _create_dlq(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]})})
    return url, arn


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern))["RuleArn"]

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name, arn


def _drain_until(ctx, url: str, until, timeout_s: float = _DELIVERY_TIMEOUT_S) -> list[dict]:
    sqs = ctx.client("sqs")
    got: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                       MessageAttributeNames=["All"]).get("Messages", []):
            got.append({"body": json.loads(msg["Body"]),
                        "attrs": {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if until(got):
            return got
    raise AssertionError(
        f"the dead-letter queue did not receive both out-of-window events within {timeout_s}s; "
        f"{len(got)} message(s) received"
    )


def _written(logs, group: str, marker: str) -> dict[str, int]:
    """{event id: log timestamp} for every log event in the group carrying ``marker``."""
    out = {}
    for page in logs.get_paginator("filter_log_events").paginate(logGroupName=group):
        for e in page["events"]:
            env = json.loads(e["message"])
            if env.get("detail", {}).get("m") == marker:
                out[env["id"]] = e["timestamp"]
    return out


def _poll_written(logs, group: str, marker: str, want, timeout_s: float = 60.0) -> dict[str, int]:
    deadline = time.monotonic() + timeout_s
    while True:
        got = _written(logs, group, marker)
        if want(got) or time.monotonic() > deadline:
            return got
        time.sleep(3)


def _publish_until_written(ctx, events, logs, bus: str, source: str, group: str) -> None:
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline:
        marker = ctx.unique_name("live-")
        events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "live",
                                    "Detail": json.dumps({"m": marker})}])
        if _poll_written(logs, group, marker, want=bool, timeout_s=15.0):
            return
    raise AssertionError(f"no liveness event reached the log group within {_DELIVERY_TIMEOUT_S}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
