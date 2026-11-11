"""op-contract-put-composite-alarm."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-put-composite-alarm"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A composite alarm's state follows its AlarmRule as child alarms flip, and a syntactically malformed AlarmRule is rejected."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-caw-ns-")
    alarm1 = ctx.unique_name("sim2real-behav-child1-")
    alarm2 = ctx.unique_name("sim2real-behav-child2-")
    composite = ctx.unique_name("sim2real-behav-composite-")

    for alarm_name in (alarm1, alarm2):
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=ns,
            MetricName="Latency",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            Tags=[{"Key": "team", "Value": "sim2real"}],
        )
        ctx.on_cleanup(lambda n=alarm_name: cw.delete_alarms(AlarmNames=[n]))

    alarm_rule = f'ALARM("{alarm1}") AND ALARM("{alarm2}")'
    cw.put_composite_alarm(AlarmName=composite, AlarmRule=alarm_rule, Tags=[{"Key": "team", "Value": "sim2real"}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    # force both children into ALARM: the AND rule must drive the composite into ALARM
    cw.set_alarm_state(AlarmName=alarm1, StateValue="ALARM", StateReason="forced-for-test")
    cw.set_alarm_state(AlarmName=alarm2, StateValue="ALARM", StateReason="forced-for-test")
    state = _poll_until(lambda: _composite_state(cw, composite), lambda s: s == "ALARM", timeout_s=90)
    assert state == "ALARM", f"expected the AND composite to derive ALARM once both children ALARM, got {state!r}"

    # flip one child back to OK: the AND rule must fall out of ALARM
    cw.set_alarm_state(AlarmName=alarm2, StateValue="OK", StateReason="forced-for-test")
    state = _poll_until(lambda: _composite_state(cw, composite), lambda s: s == "OK", timeout_s=90)
    assert state == "OK", f"expected the AND composite to fall out of ALARM once one child is OK, got {state!r}"

    # A syntactically malformed AlarmRule -- unbalanced parentheses -- can never be a
    # valid boolean expression under any grammar, so it is unambiguously rejected (unlike
    # an unrecognized function name, e.g. "BOGUSFUNC(...)", or a rule built purely from
    # repeated "TRUE" boolean-literal tokens, both of which real CloudWatch accepts
    # without complaint). The existing valid AlarmRule definition is left untouched.
    bad_rule = f'ALARM("{alarm1}") AND ALARM("{alarm2}"'
    code, message = _client_error(lambda: cw.put_composite_alarm(AlarmName=composite, AlarmRule=bad_rule))
    # A syntax-level AlarmRule refusal is always
    # "ValidationError" with a message of the form "Error in AlarmRule [...]" -- a PARSE failure,
    # distinguished by message shape from the "do not exist" refusal an unknown-child reference
    # gets. It does not vary by parameter; a code, not a class of codes.
    assert code == "ValidationError", f"expected a ValidationError for a malformed AlarmRule, got {code}"
    expected_message = f"Error in AlarmRule [Unsupported token '<EOF>' at char {len(bad_rule)}]"
    assert message == expected_message, (
        f"a syntactically malformed rule must be refused as a PARSE failure with {expected_message!r}, got {message!r}"
    )
    unchanged = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"][0]
    assert unchanged["AlarmRule"] == alarm_rule, (
        f"a rejected AlarmRule update must leave the stored rule untouched, expected {alarm_rule!r}, "
        f"got {unchanged['AlarmRule']!r}"
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


def _composite_state(cw, name):
    alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    return alarms[0]["StateValue"] if alarms else None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
