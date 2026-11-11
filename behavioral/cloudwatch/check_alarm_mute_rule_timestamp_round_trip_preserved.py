"""alarm-mute-rule-timestamp-round-trip-preserved."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-timestamp-round-trip-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An at(...) mute rule with StartDate/ExpireDate fails with ValidationError "Can not set start
    or expire dates for At expressions" and is not created (ResourceNotFoundException, empty
    message); a cron(...) rule returns its StartDate/ExpireDate exactly and reads SCHEDULED."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cw-mutetarget-")
    bad_rule_name = ctx.unique_name("sim2real-behav-cw-muterule-bad-")
    rule_name = ctx.unique_name("sim2real-behav-cw-muterule-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real-behav-cw-mutens-"),
        MetricName="FakeMetricForMuteTest",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    now = datetime.now(timezone.utc).replace(microsecond=0)
    # StartDate/ExpireDate only support minute-level precision (seconds must be
    # zero) -- use minute-aligned timestamps so the round-trip assertion targets
    # the actual supported granularity rather than a precision AWS itself rejects.
    start_date = (now + timedelta(days=10)).replace(second=0)
    expire_date = (now + timedelta(days=20)).replace(second=0)

    # Negative control: `at(...)` + StartDate/ExpireDate is a nonsensical
    # combination and must be rejected, and the rule must never be created.
    at_expr = (now + timedelta(days=3)).strftime("at(%Y-%m-%dT%H:%M)")
    error = _client_error(
        lambda: cw.put_alarm_mute_rule(
            Name=bad_rule_name,
            Rule={"Schedule": {"Expression": at_expr, "Duration": "PT1H", "Timezone": "UTC"}},
            MuteTargets={"AlarmNames": [alarm_name]},
            StartDate=start_date,
            ExpireDate=expire_date,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    assert error["Code"] == "ValidationError", f"unexpected code: {error['Code']!r}"
    expected_at = "Can not set start or expire dates for At expressions"
    assert error.get("Message") == expected_at, (
        f"expected message {expected_at!r}, got {error.get('Message')!r}"
    )
    not_found = _client_error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=bad_rule_name))
    assert not_found["Code"] == "ResourceNotFoundException", (
        f"expected GetAlarmMuteRule to fail with ResourceNotFoundException for a rule that was "
        f"never created, got {not_found['Code']!r}"
    )
    expected_nf = ""  # real AWS returns an empty message for this code
    assert not_found.get("Message") == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found.get('Message')!r}"
    )

    # Positive round trip: StartDate/ExpireDate are only accepted alongside a
    # recurring `cron(...)` schedule expression -- and must be preserved exactly,
    # with no rounding/truncation of the second-precision timestamps.
    cron_expr = "cron(0 2 * * ?)"

    cw.put_alarm_mute_rule(
        Name=rule_name,
        Rule={"Schedule": {"Expression": cron_expr, "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        StartDate=start_date,
        ExpireDate=expire_date,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert got["StartDate"] == start_date, f"{got['StartDate']!r} != {start_date!r}"
    assert got["ExpireDate"] == expire_date, f"{got['ExpireDate']!r} != {expire_date!r}"
    # Both dates are well in the future, so the rule's computed status must be SCHEDULED.
    assert got["Status"] == "SCHEDULED", got["Status"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so an emulator that
    accepts input AWS refuses is never reported as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

