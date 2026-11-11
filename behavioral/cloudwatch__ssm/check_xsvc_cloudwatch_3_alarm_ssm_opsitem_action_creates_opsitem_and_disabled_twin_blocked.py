"""xsvc-cloudwatch-3-alarm-ssm-opsitem-action-creates-opsitem-and-disabled-twin-blocked."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-3-alarm-ssm-opsitem-action-creates-opsitem-and-disabled-twin-blocked"
GROUP = "alerting"
SERVICES = ["cloudwatch", "ssm"]

_DELIVERY_BUDGET_S = 180.0


@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An alarm action `...:opsitem:3#CATEGORY=Availability` creates an OpsItem with severity 3 and
    category Availability naming the alarm; a twin with ActionsEnabled=False forced to ALARM at the
    same instant creates none until EnableAlarmActions and a fresh OK -> ALARM transition.
    """
    cw = ctx.client("cloudwatch")
    ssm = ctx.client("ssm")
    account = ctx.client("sts").get_caller_identity()["Account"]
    since = datetime.now(timezone.utc) - timedelta(minutes=2)
    namespace = ctx.unique_name("sim2real/xsvc-cwssm-")
    action = f"arn:aws:ssm:{ctx.region}:{account}:opsitem:3#CATEGORY=Availability"

    alarms = {}
    for key, enabled in (("armed", True), ("disarmed", False)):
        name = ctx.unique_name(f"sim2real-xsvc-cwssm-{key}-")
        # Registered BEFORE the alarm can act: whatever OpsItem it creates is found by name and deleted.
        ctx.on_cleanup(lambda n=name: _delete_ops_items(ssm, n, since))
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName="Never", Statistic="Maximum",
            Period=60, EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore", AlarmActions=[action], ActionsEnabled=enabled,
            Tags=[{"Key": "sim2real", "Value": "cloudwatch__ssm"}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        alarms[key] = name
    stored = _alarm(cw, alarms["armed"])
    assert stored["AlarmActions"] == [action], f"AlarmActions stored as {stored['AlarmActions']!r}"
    assert _alarm(cw, alarms["disarmed"])["ActionsEnabled"] is False, "disarmed alarm stored ActionsEnabled=True"

    for key, name in alarms.items():
        cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason=f"sim2real forced {key}")

    # Positive control (and the barrier): the armed alarm's action succeeds and its OpsItem appears.
    # CloudWatch acts through the AWSServiceRoleForCloudWatchAlarms_ActionSSM service-linked role,
    # which PutMetricAlarm creates on an account that lacks it; a role that young can fail the first
    # action, so the armed alarm is re-driven (fresh OK -> ALARM) while its action reads Failed.
    rounds = _drive_until_succeeded(cw, alarms["armed"], _DELIVERY_BUDGET_S, already_forced=True)
    found = _poll(lambda: _ops_items(ssm, alarms["armed"], since), lambda f: len(f) >= 1,
                  _DELIVERY_BUDGET_S, f"an OpsItem naming alarm {alarms['armed']!r} (action rounds {rounds!r})")
    item = found[0]
    assert item.get("Severity") == "3", f"OpsItem severity {item.get('Severity')!r}, the ARN asked for 3: {item!r}"
    assert item.get("Category") == "Availability", f"OpsItem category {item.get('Category')!r}: {item!r}"
    assert item.get("Status") == "Open", f"a fresh OpsItem must be Open, got {item.get('Status')!r}"
    assert item.get("Source") == "CloudWatch Alarm", f"OpsItem source {item.get('Source')!r}"
    resources = json.loads(item["OperationalData"]["/aws/resources"]["Value"])
    assert resources == [{"arn": stored["AlarmArn"]}], (
        f"OpsItem /aws/resources is {resources!r}, expected exactly the alarm ARN {stored['AlarmArn']!r}"
    )

    # Effect absent: the disabled twin created nothing.
    assert _alarm(cw, alarms["disarmed"])["StateValue"] == "ALARM", "the disarmed alarm left ALARM"
    stray = _ops_items(ssm, alarms["disarmed"], since)
    assert stray == [], f"the alarm with ActionsEnabled=False created OpsItem(s) {stray!r}"
    assert _history(cw, alarms["disarmed"]) == [], "the disarmed alarm recorded Action items while disabled"

    # Repair: re-enable actions and drive a fresh OK -> ALARM.
    dname = alarms["disarmed"]
    cw.enable_alarm_actions(AlarmNames=[dname])
    assert _alarm(cw, dname)["ActionsEnabled"] is True, "EnableAlarmActions did not set ActionsEnabled"
    _drive_until_succeeded(cw, dname, _DELIVERY_BUDGET_S, already_forced=False)
    again = _poll(lambda: _ops_items(ssm, dname, since), lambda f: len(f) >= 1,
                  _DELIVERY_BUDGET_S, f"an OpsItem naming the re-armed alarm {dname!r}")
    assert again[0].get("Category") == "Availability", f"re-armed OpsItem {again[0]!r}"


# ===== shared helpers =====


def _drive_until_succeeded(cw, name: str, budget_s: float, already_forced: bool) -> list:
    """Force OK -> ALARM until that transition's Action item reads Succeeded; return each round's state.
    With already_forced the caller's own SetAlarmState is round one, so it is awaited, not repeated."""
    deadline = time.monotonic() + budget_s
    rounds = []
    first = already_forced
    while True:
        seen = 0 if first else len(_history(cw, name))
        if not first:
            cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="sim2real reset")
            _poll(lambda: _alarm(cw, name)["StateValue"], lambda v: v == "OK", 30.0, f"{name} to read OK")
            cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="sim2real re-driven")
        first = False
        items = _poll(lambda: _history(cw, name), lambda h: len(h) > seen, 60.0,
                      f"{name}'s Action history to record its attempt")
        data = json.loads(items[0]["HistoryData"])
        rounds.append(data.get("actionState"))
        if rounds[-1] == "Succeeded":
            return rounds
        assert time.monotonic() < deadline, f"{name}'s action never succeeded; rounds {rounds!r}, last {data!r}"
        time.sleep(2.0)


def _ops_items(ssm, alarm_name: str, since) -> list:
    """OpsItems created since `since` that name this alarm anywhere in their summary. The CreatedTime
    filter plus the unique alarm name makes the match a property of the query, not of the account."""
    out, token = [], None
    while True:
        kw = {"OpsItemFilters": [{"Key": "CreatedTime", "Values": [since.strftime("%Y-%m-%dT%H:%M:%SZ")],
                                  "Operator": "GreaterThan"}], "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        resp = ssm.describe_ops_items(**kw)
        out.extend(s for s in resp.get("OpsItemSummaries", []) if alarm_name in json.dumps(s, default=str))
        token = resp.get("NextToken")
        if not token:
            return out


def _delete_ops_items(ssm, alarm_name: str, since) -> None:
    for s in _ops_items(ssm, alarm_name, since):
        try:
            ssm.delete_ops_item(OpsItemId=s["OpsItemId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "OpsItemNotFoundException":
                raise


def _alarm(cw, name: str) -> dict:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


def _history(cw, name: str) -> list:
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="Action", AlarmTypes=["MetricAlarm"]
    ):
        items.extend(page["AlarmHistoryItems"])
    return items


def _poll(fetch, pred, budget_s: float, what: str):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
