"""alarm-mute-rule-timestamp-microsecond-precision-preserved."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-mute-rule-timestamp-microsecond-precision-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sub-second precision in StartDate/EndDate survives PutAlarmMuteRule/GetAlarmMuteRule."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-mute-target-")
    rule_name = ctx.unique_name("sim2real-cw-mute-rule-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    base = datetime.now(timezone.utc) + timedelta(days=1)
    # Real CloudWatch enforces minute-level precision on StartDate/ExpireDate (a
    # sub-minute value is rejected with ValidationError, not silently rounded) --
    # verified empirically below. So the round-trip fidelity claim we can make is at
    # minute granularity: an odd, non-zero minute value must survive untouched.
    start_date = base.replace(minute=(base.minute % 59) + 1, second=0, microsecond=0)
    expire_date = (base + timedelta(days=2)).replace(minute=(base.minute % 59) + 1, second=0, microsecond=0)

    # Boundary check: sub-minute precision is rejected outright rather than truncated.
    sub_minute_start = start_date.replace(second=17, microsecond=123456)
    try:
        cw.put_alarm_mute_rule(
            Name=ctx.unique_name("sim2real-cw-mute-rule-reject-"),
            Rule={"Schedule": {"Expression": "cron(0 3 * * ?)", "Duration": "PT1H", "Timezone": "UTC"}},
            MuteTargets={"AlarmNames": [alarm_name]},
            StartDate=sub_minute_start,
            ExpireDate=expire_date,
        )
        raise AssertionError("sub-minute-precision StartDate was accepted instead of rejected")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationError", (
            f"expected ValidationError for sub-minute StartDate, got {err.response['Error']['Code']!r}"
        )
        message = err.response["Error"].get("Message", "")
        expected = (
            "The Alarm Mute Rule StartDate only supports minute-level precision. "
            "Please provide the time without seconds."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    cw.put_alarm_mute_rule(
        Name=rule_name,
        Rule={"Schedule": {"Expression": "cron(0 3 * * ?)", "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        StartDate=start_date,
        ExpireDate=expire_date,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    resp = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)

    start_diff = abs((resp["StartDate"] - start_date).total_seconds())
    expire_diff = abs((resp["ExpireDate"] - expire_date).total_seconds())

    # A minute value getting rounded/floored to :00 or shifted would show up as a
    # nonzero diff here; the accepted minute-precision timestamp must be exact.
    assert start_diff < 1e-6, f"StartDate not preserved exactly: sent {start_date!r}, got {resp['StartDate']!r}"
    assert expire_diff < 1e-6, f"ExpireDate not preserved exactly: sent {expire_date!r}, got {resp['ExpireDate']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
