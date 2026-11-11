"""get-alarm-mute-rule-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-alarm-mute-rule-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAlarmMuteRule on a name that was never created returns ResourceNotFoundException,
    while a sibling rule created in the same run resolves normally (positive control) --
    so the rejection can't be explained by a GetAlarmMuteRule that never actually works."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "get_alarm_mute_rule"):
        raise AssertionError(
            "cloudwatch client lacks get_alarm_mute_rule; botocore predates the AlarmMuteRule API"
        )

    real_name = ctx.unique_name("sim2real-mute-real-")
    rule = {"Schedule": {"Expression": "cron(0 4 * * ?)", "Duration": "PT1H", "Timezone": "UTC"}}
    cw.put_alarm_mute_rule(Name=real_name, Description="positive control", Rule=rule)
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=real_name))

    # Positive control: a rule that genuinely exists resolves fine, so a stub that always
    # answers ResourceNotFoundException regardless of the requested name cannot pass this
    # check merely by rejecting everything.
    real = cw.get_alarm_mute_rule(AlarmMuteRuleName=real_name)
    assert real["Name"] == real_name, f"expected {real_name}, got {real.get('Name')}"

    missing_name = ctx.unique_name("sim2real-mute-missing-")
    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # GetAlarmMuteRule answers not-found with an empty message.
    assert message == "", f"unexpected GetAlarmMuteRule message {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
