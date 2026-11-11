"""alarm-mute-rule-expires-after-ttl."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


# timing:real-time — ttl: 68 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A mute rule with an ExpireDate 1-2 minutes out reads ACTIVE or SCHEDULED, is never
    EXPIRED until 10 s before that date, then reads EXPIRED; after DeleteAlarmMuteRule,
    GetAlarmMuteRule fails with ResourceNotFoundException and an empty message."""
    cw = ctx.client("cloudwatch")
    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    alarm_name = ctx.unique_name("sim2real-behav-mutealarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real/behav/"),
        MetricName="MuteProbe",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-behav-muterule-")
    # PutAlarmMuteRule only accepts minute-level precision for ExpireDate. Floor `now` to the
    # minute boundary *before* adding the TTL, so the buffer is always 60-120s and the ExpireDate
    # never lands within milliseconds of the request near a minute boundary.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    expire_date = now + timedelta(minutes=2)

    cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="sim2real-behav TTL expiry check",
        Rule={"Schedule": {"Expression": "cron(0 3 * * ?)", "Duration": "PT1M", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        ExpireDate=expire_date,
    )

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert got["Status"] in ("ACTIVE", "SCHEDULED"), f"unexpected initial status: {got['Status']}"

    # Time is two-sided: prove the rule does NOT expire early, not just that it eventually does.
    # Poll up to shortly before ExpireDate and demand it is not EXPIRED at every read, so a target
    # that mutes for a fixed duration unrelated to the ExpireDate cannot pass by accident.
    _assert_no_premature_expiry(ctx, rule_name, deadline=expire_date - timedelta(seconds=10))

    _poll_for_status(ctx, rule_name, "EXPIRED", timeout_s=90.0)

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)

    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _assert_no_premature_expiry(ctx, rule_name: str, deadline: datetime) -> None:
    cw = ctx.client("cloudwatch")
    while True:
        remaining_s = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining_s <= 0:
            return
        status = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"]
        assert status != "EXPIRED", (
            f"mute rule reported EXPIRED before its ExpireDate (checked until {deadline.isoformat()}), "
            f"status={status}"
        )
        time.sleep(min(5.0, remaining_s))


def _poll_for_status(ctx, rule_name: str, target_status: str, timeout_s: float = 90.0) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)["Status"]
        if status == target_status:
            return status
        time.sleep(3)
    raise AssertionError(f"mute rule never reached {target_status} within {timeout_s}s, last status={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
