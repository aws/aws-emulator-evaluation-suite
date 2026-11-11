"""alarm-mute-rule-schedule-timestamp-preserved."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-schedule-timestamp-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartDate/ExpireDate timestamps supplied to PutAlarmMuteRule come back exact
    (to the second) from GetAlarmMuteRule -- not reformatted, truncated, or rounded to a
    coarser boundary."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-mute-")
    # PutAlarmMuteRule only supports minute-level precision on StartDate/ExpireDate
    # (real AWS rejects sub-minute precision with ValidationError), so both timestamps
    # must be rounded to the minute for a legitimate round-trip check.
    start_date = datetime.now(timezone.utc).replace(second=0, microsecond=0) + timedelta(
        days=1
    )
    expire_date = start_date + timedelta(days=2, hours=3, minutes=17)

    try:
        cw.put_alarm_mute_rule(
            Name=name,
            Rule={
                "Schedule": {
                    "Expression": "cron(0 2 * * ?)",
                    "Duration": "PT2H",
                    "Timezone": "UTC",
                }
            },
            Tags=[{"Key": "sim2real", "Value": "true"}],
            StartDate=start_date,
            ExpireDate=expire_date,
        )
    except AttributeError:
        raise AssertionError(
            "installed botocore has no PutAlarmMuteRule/GetAlarmMuteRule operation model "
            "(alarm mute rules are a newer CloudWatch API); would be closed by upgrading "
            "the botocore/boto3 pin used to build the test image"
        )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=name))

    resp = cw.get_alarm_mute_rule(AlarmMuteRuleName=name)
    assert resp["Name"] == name, f"Name mismatch: {resp['Name']!r} != {name!r}"
    assert resp["StartDate"] == start_date, (
        f"StartDate mangled: {resp['StartDate']!r} != {start_date!r}"
    )
    assert resp["ExpireDate"] == expire_date, (
        f"ExpireDate mangled: {resp['ExpireDate']!r} != {expire_date!r}"
    )
    assert resp["Status"] == "SCHEDULED", f"Status: expected SCHEDULED, got {resp['Status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
