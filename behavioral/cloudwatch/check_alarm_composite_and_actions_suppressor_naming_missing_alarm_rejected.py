"""alarm-composite-and-actions-suppressor-naming-missing-alarm-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-suppressor-naming-missing-alarm-rejected"
GROUP = "validation"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A composite whose ActionsSuppressor names a missing alarm is refused on create (none is left)
    and on update (suppressor and AlarmRule unchanged) with ValidationError "Could not save the
    composite alarm as the actions suppressor alarm [<arn>] does not exist"; a real one is stored."""
    cw = ctx.client("cloudwatch")
    child = ctx.unique_name("sim2real-cwsupp-child-")
    suppressor = ctx.unique_name("sim2real-cwsupp-sup-")
    missing = ctx.unique_name("sim2real-cwsupp-missing-")
    for name in (child, suppressor):
        cw.put_metric_alarm(
            AlarmName=name, Namespace=ctx.unique_name("sim2real/cwsupp-"), MetricName="m",
            Statistic="Maximum", Period=60, EvaluationPeriods=1, Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold", ActionsEnabled=False,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
    rule = f'ALARM("{child}")'

    good = ctx.unique_name("sim2real-cwsupp-good-")
    cw.put_composite_alarm(
        AlarmName=good, AlarmRule=rule, ActionsSuppressor=suppressor,
        ActionsSuppressorWaitPeriod=60, ActionsSuppressorExtensionPeriod=60,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[good]))
    stored = _composite(cw, good)
    assert stored is not None, f"the positive-control composite {good!r} was not created"
    # ActionsSuppressor is stored verbatim as the name passed, not as an ARN.
    assert stored["ActionsSuppressor"] == suppressor, (
        f"positive control stored ActionsSuppressor {stored.get('ActionsSuppressor')!r}"
    )
    good_suppressor = stored["ActionsSuppressor"]

    bad = ctx.unique_name("sim2real-cwsupp-bad-")
    code, message, created = _attempt(lambda: cw.put_composite_alarm(
        AlarmName=bad, AlarmRule=rule, ActionsSuppressor=missing,
        ActionsSuppressorWaitPeriod=60, ActionsSuppressorExtensionPeriod=60,
    ))
    if created:
        ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[bad]))
    assert code == "ValidationError", (
        f"a composite whose ActionsSuppressor {missing!r} does not exist must be refused with "
        f"ValidationError; got {code!r} {message!r}"
    )
    expected = (
        f"Could not save the composite alarm as the actions suppressor alarm "
        f"[arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{missing}] does not exist"
    )
    assert message == expected, f"the refusal must name the missing suppressor: expected {expected!r}, got {message!r}"
    assert _composite(cw, bad) is None, f"the refused create left composite {bad!r} behind"

    code, message, _ = _attempt(lambda: cw.put_composite_alarm(
        AlarmName=good, AlarmRule=rule, ActionsSuppressor=missing,
        ActionsSuppressorWaitPeriod=60, ActionsSuppressorExtensionPeriod=60,
    ))
    assert code == "ValidationError", (
        f"re-pointing an existing composite at a missing suppressor must be refused with "
        f"ValidationError; got {code!r} {message!r}"
    )
    expected = (
        f"Could not save the composite alarm as the actions suppressor alarm "
        f"[arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{missing}] does not exist"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    after = _composite(cw, good)
    assert after is not None and after["ActionsSuppressor"] == good_suppressor, (
        f"the refused update changed the stored suppressor: {after and after.get('ActionsSuppressor')!r}, "
        f"expected {good_suppressor!r}"
    )
    assert after["AlarmRule"] == rule, f"the refused update changed AlarmRule to {after['AlarmRule']!r}"


def _composite(cw, name: str):
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    return found[0] if found else None


def _attempt(fn):
    """(code, message, succeeded). Never a falsy code on unexpected success: '<SUCCEEDED>'."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or "", False
    return "<SUCCEEDED>", "the call was accepted", True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
