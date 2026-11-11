"""get-alarm-mute-rule-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-alarm-mute-rule-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAlarmMuteRule on an unknown rule name fails with ResourceNotFoundException and an empty
    message, while a rule that exists resolves by name."""
    cw = ctx.client("cloudwatch")
    real_name = ctx.unique_name("sim2real-mute-rule-real-")
    missing_name = ctx.unique_name("sim2real-mute-rule-missing-")

    cw.put_alarm_mute_rule(
        Name=real_name,
        Description="positive control",
        Rule={"Schedule": {"Expression": "cron(0 4 * * ?)", "Duration": "PT1H", "Timezone": "UTC"}},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=real_name))

    # Positive control: a rule that really exists resolves fine, so the not-found
    # path below can't be explained by GetAlarmMuteRule failing on every call.
    real = cw.get_alarm_mute_rule(AlarmMuteRuleName=real_name)
    assert real["Name"] == real_name, f"expected {real_name}, got {real.get('Name')}"

    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # GetAlarmMuteRule answers not-found with an empty message.
    assert message == "", f"unexpected GetAlarmMuteRule message {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so an over-permissive target's acceptance is never reported as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
