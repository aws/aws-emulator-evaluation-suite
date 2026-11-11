"""put-alarm-mute-rule-crud-visible-immediately-in-list-alarm-mute-rules."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-crud-visible-immediately-in-list-alarm-mute-rules"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created alarm mute rule appears in ListAlarmMuteRules
    immediately, and disappears immediately after DeleteAlarmMuteRule."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-mute-")

    def _name_from_arn(arn):
        # arn:aws:cloudwatch:region:account-id:alarm-mute-rule:NAME
        return arn.split(":alarm-mute-rule:", 1)[-1]

    def _names():
        names = set()
        next_token = None
        while True:
            kwargs = {"NextToken": next_token} if next_token else {}
            resp = cw.list_alarm_mute_rules(**kwargs)
            names.update(
                _name_from_arn(s["AlarmMuteRuleArn"])
                for s in resp.get("AlarmMuteRuleSummaries", [])
                if s.get("AlarmMuteRuleArn")
            )
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return names

    cw.put_alarm_mute_rule(
        Name=name,
        Rule={"Schedule": {"Expression": "cron(0 4 * * *)", "Duration": "PT1H"}},
    )
    deleted = False
    ctx.on_cleanup(lambda: None if deleted else cw.delete_alarm_mute_rule(AlarmMuteRuleName=name))

    present = _poll_until(_names, lambda ns: name in ns, timeout_s=15.0, interval_s=1.0)
    assert name in present, f"expected {name!r} in ListAlarmMuteRules within 15s, got {present!r}"

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)
    deleted = True
    absent = _poll_until(_names, lambda ns: name not in ns, timeout_s=15.0, interval_s=1.0)
    assert name not in absent, f"expected {name!r} removed from ListAlarmMuteRules within 15s, still in {absent!r}"

    code, message = _client_error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name))
    assert code == "ResourceNotFoundException", (
        f"expected GetAlarmMuteRule({name!r}) to fail with ResourceNotFoundException after delete, got {code!r}"
    )
    expected_message = ""  # AWS returns this refusal with an empty message
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
