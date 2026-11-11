"""put-alarm-mute-rule-duration-exceeds-max-rejected."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-duration-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule rejects a Schedule.Duration of P16D (over the documented 15-day maximum) with
    ValidationError "The Alarm Mute Rule Duration cannot exceed 15 days." and creates no rule, while a
    PT30M duration is accepted and reads back as PT30M."""
    cw = ctx.client("cloudwatch")
    good_name = ctx.unique_name("sim2real-mute-ok-")
    bad_name = ctx.unique_name("sim2real-mute-bad-")
    future = (dt.datetime.utcnow() + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
    expr = f"at({future})"

    code, message = _client_error(
        lambda: cw.put_alarm_mute_rule(
            Name=bad_name,
            Rule={"Schedule": {"Expression": expr, "Duration": "P16D"}},
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = 'The Alarm Mute Rule Duration cannot exceed 15 days.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected rule was never created
    not_found_code, not_found_message = _client_error(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=bad_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for never-created rule, got {not_found_code!r}"
    )
    expected_not_found_message = ""  # AWS returns this refusal with an empty message
    assert not_found_message == expected_not_found_message, (
        f"expected message {expected_not_found_message!r}, got {not_found_message!r}"
    )

    # positive control: a duration within the allowed range succeeds
    cw.put_alarm_mute_rule(
        Name=good_name,
        Rule={"Schedule": {"Expression": expr, "Duration": "PT30M"}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=good_name))
    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=good_name)
    assert got["Rule"]["Schedule"]["Duration"] == "PT30M", (
        f"expected Duration PT30M on the accepted rule, got {got['Rule']['Schedule'].get('Duration')!r}"
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
