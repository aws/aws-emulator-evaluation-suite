"""alarm-mute-rule-status-lifecycle."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-status-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A daily-cron mute rule whose StartDate is in the future reads SCHEDULED; upserted to a
    one-time at(...) occurrence at the next minute it still reads SCHEDULED, then ACTIVE once the
    occurrence opens and EXPIRED once its Duration elapses."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-mutetarget-")
    mute_rule_name = ctx.unique_name("sim2real-behav-muterule-")
    namespace = ctx.unique_name("Sim2RealBehav/")
    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}]

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    mute_targets = {"AlarmNames": [alarm_name]}

    # 1. A daily-cron rule whose outer StartDate is far in the future is SCHEDULED -- the
    # schedule cannot have opened its first occurrence yet.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    cw.put_alarm_mute_rule(
        Name=mute_rule_name,
        Rule={"Schedule": {"Expression": "cron(0 2 * * ?)", "Duration": "PT2H", "Timezone": "UTC"}},
        MuteTargets=mute_targets,
        StartDate=now + timedelta(days=365),
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name))
    scheduled = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)
    assert scheduled["Status"] == "SCHEDULED", scheduled["Status"]

    # 2. Re-point the SAME rule (upsert) at a one-time at(...) occurrence pinned to the next
    # minute boundary. (Real AWS rejects StartDate/ExpireDate alongside an at(...) expression --
    # ValidationError "Can not set start or expire dates for At expressions" -- so the occurrence
    # window itself is the only thing gating status here.) Immediately after the upsert -- before
    # the occurrence opens -- it must still read SCHEDULED.
    next_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=1)
    if (next_minute - datetime.now(timezone.utc)).total_seconds() < 20:
        next_minute += timedelta(minutes=1)
    window_start = next_minute
    window_end = window_start + timedelta(minutes=1)
    cw.put_alarm_mute_rule(
        Name=mute_rule_name,
        Rule={"Schedule": {"Expression": f"at({window_start.strftime('%Y-%m-%dT%H:%M')})", "Duration": "PT1M"}},
        MuteTargets=mute_targets,
        Tags=tags_kv,
    )
    still_scheduled = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)
    assert still_scheduled["Status"] == "SCHEDULED", still_scheduled["Status"]

    # Once the occurrence opens, the SAME rule reports ACTIVE.
    active = _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=(window_start - datetime.now(timezone.utc)).total_seconds() + 30,
        interval_s=3,
    )
    assert active == "ACTIVE", active

    # 3. Once the occurrence's Duration elapses, the SAME rule reports EXPIRED.
    expired = _poll_until(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_rule_name)["Status"],
        lambda status: status == "EXPIRED",
        timeout_s=(window_end - datetime.now(timezone.utc)).total_seconds() + 30,
        interval_s=3,
    )
    assert expired == "EXPIRED", expired


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
