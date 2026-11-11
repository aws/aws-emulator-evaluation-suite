"""put-alarm-mute-rule-timestamp-precision-round-trip."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-timestamp-precision-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAlarmMuteRule returns minute-precision StartDate and ExpireDate exactly as put (no timezone
    drift, no rounding), and a StartDate with seconds is rejected with ValidationError and its exact
    minute-level-precision message."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-mute-")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start_date = now + timedelta(hours=2, minutes=37)
    expire_date = now + timedelta(hours=4, minutes=11)

    cw.put_alarm_mute_rule(
        Name=name,
        Rule={"Schedule": {"Expression": "cron(0 3 * * *)", "Duration": "PT1H"}},
        StartDate=start_date,
        ExpireDate=expire_date,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=name))

    fetched = cw.get_alarm_mute_rule(AlarmMuteRuleName=name)
    assert fetched["StartDate"] == start_date, f"{fetched['StartDate']!r} != {start_date!r}"
    assert fetched["ExpireDate"] == expire_date, f"{fetched['ExpireDate']!r} != {expire_date!r}"

    # Sub-minute precision on the same field is rejected, not rounded, so the minute-level
    # round-trip above is an enforced contract.
    from botocore.exceptions import ClientError

    other_name = ctx.unique_name("sim2real-cw-mute-")
    sub_minute_start = start_date.replace(second=17)
    try:
        cw.put_alarm_mute_rule(
            Name=other_name,
            Rule={"Schedule": {"Expression": "cron(0 3 * * *)", "Duration": "PT1H"}},
            StartDate=sub_minute_start,
            ExpireDate=expire_date,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ValidationError", (
            f"expected ValidationError for sub-minute precision, got "
            f"{e.response['Error']['Code']!r}"
        )
        message = e.response["Error"].get("Message")
        expected_message = (
            'The Alarm Mute Rule StartDate only supports minute-level precision. '
            'Please provide the time without seconds.'
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=other_name))
        raise AssertionError("expected sub-minute-precision StartDate to be rejected")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
