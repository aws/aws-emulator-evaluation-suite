"""alarm-mute-rule-active-window-boundary-second-precision."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "alarm-mute-rule-active-window-boundary-second-precision"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A mute rule reads ACTIVE until its ExpireDate and EXPIRED after it, and SetAlarmState on the
    muted alarm still moves it to ALARM while the rule is ACTIVE: muting suppresses actions, not
    evaluation."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-mutealarm-")
    rule_name = ctx.unique_name("sim2real-muterule-")
    namespace = ctx.unique_name("sim2real-mute-ns-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Placeholder",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # PutAlarmMuteRule only accepts minute-level precision for StartDate/ExpireDate
    # (a non-zero seconds component is rejected with ValidationError), so the boundary
    # this check can actually probe on real AWS is the exact *minute* mark, not a
    # sub-minute second. ExpireDate is pinned to the next whole minute from "now" so the
    # active window is short (<=60s) and the poll after it stays tightly bounded.
    now_floor = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = now_floor - timedelta(minutes=2)
    expire = now_floor + timedelta(minutes=1)

    cw.put_alarm_mute_rule(
        Name=rule_name,
        # Recurring, effectively-always-on schedule so the *cron/duration* window never
        # gates the test -- only StartDate/ExpireDate (second precision) should matter here.
        Rule={"Schedule": {"Expression": "cron(* * * * *)", "Duration": "PT15M", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        StartDate=start,
        ExpireDate=expire,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    status_before_ts = datetime.now(timezone.utc)
    status_before = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"]
    assert status_before == "ACTIVE", (
        f"expected ACTIVE before ExpireDate, got {status_before} at {status_before_ts}"
    )

    # Muting suppresses actions, not state evaluation: forcing a state must still take effect.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="behavioral-check-forced")
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=30,
        interval_s=2,
    )
    assert state == "ALARM", "SetAlarmState did not take effect while the mute rule was ACTIVE"

    # Poll across the ExpireDate second: must never be seen non-ACTIVE before it, and must
    # eventually (bounded) become EXPIRED after it. The earlier status_before read already
    # counts if it landed before ExpireDate -- the ALARM-state poll above can itself eat into
    # a short (<=60s) active window, so this must not be re-zeroed to False here.
    saw_active_before_expiry = status_before_ts < expire
    flipped_to_expired = False
    seconds_until_expire = max(0.0, (expire - datetime.now(timezone.utc)).total_seconds())
    deadline = time.monotonic() + seconds_until_expire + 90
    while time.monotonic() < deadline:
        now_check = datetime.now(timezone.utc)
        status = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"]
        if now_check < expire:
            assert status == "ACTIVE", (
                f"mute rule left ACTIVE status before its ExpireDate second: {status} at {now_check}"
            )
            saw_active_before_expiry = True
        elif status == "EXPIRED":
            flipped_to_expired = True
            break
        time.sleep(1)

    assert saw_active_before_expiry, "never observed ACTIVE status before ExpireDate"
    assert flipped_to_expired, "mute rule never reached EXPIRED status after its ExpireDate second elapsed"


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
