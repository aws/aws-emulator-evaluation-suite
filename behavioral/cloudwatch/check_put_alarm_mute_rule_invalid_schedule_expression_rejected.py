"""put-alarm-mute-rule-invalid-schedule-expression-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-invalid-schedule-expression-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule rejects a Schedule.Expression that is neither cron(...) nor at(...) with
    ValidationError "Schedule is malformed." and creates no rule, while cron(0 2 * * *) is accepted and
    reads back unchanged."""
    cw = ctx.client("cloudwatch")
    bad_name = ctx.unique_name("sim2real-behav-mute-bad-")
    good_name = ctx.unique_name("sim2real-behav-mute-good-")

    code, message = _client_error(
        lambda: cw.put_alarm_mute_rule(
            Name=bad_name,
            Rule={
                "Schedule": {
                    "Expression": "not a cron or at expression!!",
                    "Duration": "PT1H",
                }
            },
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = 'Schedule is malformed.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the malformed rule was never created.
    not_found_code, not_found_message = _client_error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for never-created rule, got {not_found_code!r}"
    )
    expected_not_found_message = ""  # AWS returns this refusal with an empty message
    assert not_found_message == expected_not_found_message, (
        f"expected message {expected_not_found_message!r}, got {not_found_message!r}"
    )

    # Positive control: a syntactically valid schedule expression succeeds.
    cw.put_alarm_mute_rule(
        Name=good_name,
        Rule={
            "Schedule": {
                "Expression": "cron(0 2 * * *)",
                "Duration": "PT1H",
                "Timezone": "UTC",
            }
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=good_name))
    fetched = cw.get_alarm_mute_rule(AlarmMuteRuleName=good_name)
    assert fetched["Rule"]["Schedule"]["Expression"] == "cron(0 2 * * *)", (
        f"expected accepted rule to keep Expression 'cron(0 2 * * *)', got "
        f"{fetched['Rule']['Schedule'].get('Expression')!r}"
    )


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
