"""put-alarm-mute-rule-end-before-start-rejected."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-end-before-start-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule rejects an ExpireDate that is earlier than StartDate with a
    ValidationError, never creates the rule, and the same call with a valid
    (StartDate < ExpireDate) ordering succeeds as a SCHEDULED rule."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-mute-")
    rule = {"Schedule": {"Expression": "cron(0 2 * * ?)", "Duration": "PT2H", "Timezone": "UTC"}}
    now = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)

    bad_start = now + dt.timedelta(days=2)
    bad_expire = now + dt.timedelta(days=1)  # earlier than StartDate -> invalid combination

    code, message = _client_error(
        lambda: cw.put_alarm_mute_rule(
            Name=name, Rule=rule, StartDate=bad_start, ExpireDate=bad_expire
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = 'The Alarm Mute Rule is expired.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the mute rule was never created.
    not_found_code, not_found_message = _client_error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for never-created rule, got {not_found_code!r}"
    )
    expected_not_found_message = ""  # AWS returns this refusal with an empty message
    assert not_found_message == expected_not_found_message, (
        f"expected message {expected_not_found_message!r}, got {not_found_message!r}"
    )

    # Positive control: same call, valid StartDate < ExpireDate ordering, succeeds.
    good_start = now + dt.timedelta(days=1)
    good_expire = now + dt.timedelta(days=2)
    cw.put_alarm_mute_rule(
        Name=name,
        Rule=rule,
        StartDate=good_start,
        ExpireDate=good_expire,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=name))

    created = cw.get_alarm_mute_rule(AlarmMuteRuleName=name)
    assert created["Name"] == name, f"expected mute rule name {name!r}, got {created['Name']!r}"
    # StartDate is a day ahead, so the rule is not active yet.
    assert created["Status"] == "SCHEDULED", (
        f"expected the valid-ordering rule starting tomorrow to be SCHEDULED, got {created['Status']!r}"
    )


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

