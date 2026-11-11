"""put-alarm-mute-rule-generates-alarm-history-entry."""
from __future__ import annotations

import datetime as _dt
import time

from behavioral_harness import tags


CHECK = "put-alarm-mute-rule-generates-alarm-history-entry"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state transition of an alarm targeted by an ACTIVE mute rule writes a new alarm-history
    entry that references the mute rule."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    alarm_name = ctx.unique_name("sim2real-behav-mutealarm-")
    namespace = "Sim2RealBehavioral"
    metric_name = ctx.unique_name("MuteRuleMetric-")
    action_arn = f"arn:aws:sns:{ctx.region}:{account}:sim2real-behav-mute-action"

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        AlarmActions=[action_arn],
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="OK", StateReason="baseline for mute test"
    )

    baseline = cw.describe_alarm_history(AlarmName=alarm_name, MaxRecords=100)[
        "AlarmHistoryItems"
    ]
    baseline_count = len(baseline)

    # The one-time window opens at the start of the current minute, so it is open on every run.
    start_at = _dt.datetime.now(_dt.timezone.utc).replace(second=0, microsecond=0)
    at_expr = f"at({start_at.strftime('%Y-%m-%dT%H:%M')})"

    mute_rule_name = ctx.unique_name("sim2real-behav-mute-")
    cw.put_alarm_mute_rule(
        Name=mute_rule_name,
        Rule={"Schedule": {"Expression": at_expr, "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name))

    active = False
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while time.monotonic() < deadline:
        status = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)["Status"]
        if status == "ACTIVE":
            active = True
            break
        time.sleep(1)
    if not active and _budget_spent(ctx):
        raise TimeoutError(f"mute rule {mute_rule_name} to reach ACTIVE: the run budget ended first; "
                           f"not graded")
    assert active, f"mute rule {mute_rule_name} never reached ACTIVE status"

    # The muted action of this transition is what writes the history entry.
    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="trigger under mute"
    )

    new_items: list[dict] = []
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while time.monotonic() < deadline:
        items = cw.describe_alarm_history(AlarmName=alarm_name, MaxRecords=100)[
            "AlarmHistoryItems"
        ]
        if len(items) > baseline_count:
            new_items = items[: len(items) - baseline_count]
            break
        time.sleep(1)

    if not new_items and _budget_spent(ctx):
        raise TimeoutError(f"a new alarm-history entry for {alarm_name}: the run budget ended first; "
                           f"not graded")
    assert new_items, (
        f"no new alarm-history entry appeared for {alarm_name} after the "
        f"muted state transition (baseline={baseline_count})"
    )

    matched = [
        i
        for i in new_items
        if mute_rule_name in i.get("HistorySummary", "") or mute_rule_name in i.get("HistoryData", "")
    ]
    assert matched, f"expected an alarm-history entry referencing mute rule {mute_rule_name!r}, got {new_items!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
