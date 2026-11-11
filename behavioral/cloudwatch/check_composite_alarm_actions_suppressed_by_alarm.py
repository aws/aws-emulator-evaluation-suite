"""composite-alarm-actions-suppressed-by-alarm."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-actions-suppressed-by-alarm"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


# timing:real-time — cooldown: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A composite alarm with an ActionsSuppressor in ALARM reports ActionsSuppressedBy == 'Alarm' while itself ALARM, and stops reporting it once the suppressor leaves ALARM."""
    cw = ctx.client("cloudwatch")
    suppressor_name = ctx.unique_name("sim2real-suppressor-")
    child_name = ctx.unique_name("sim2real-child-")
    composite_name = ctx.unique_name("sim2real-composite-")
    namespace = ctx.unique_name("Sim2Real-CW-")
    tags_kv = [{"Key": "sim2real-check", "Value": CHECK}]

    # Neither metric is ever published; 'ignore' keeps each forced state, so no evaluation reclaims
    # the suppressor or the child while the composite is observed.
    cw.put_metric_alarm(
        AlarmName=suppressor_name,
        Namespace=namespace,
        MetricName="SuppressorMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[suppressor_name]))

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName="ChildMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_name]))

    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        ActionsSuppressor=suppressor_name,
        ActionsSuppressorWaitPeriod=60,
        ActionsSuppressorExtensionPeriod=60,
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    cw.set_alarm_state(AlarmName=suppressor_name, StateValue="ALARM", StateReason="suppressor-armed")
    cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason="child-armed")

    composite = _poll_until(
        lambda: _get_composite(cw, composite_name),
        lambda c: c is not None and c.get("ActionsSuppressedBy") == "Alarm",
        timeout_s=120.0,
    )
    if composite is None or composite.get("ActionsSuppressedBy") != "Alarm":
        raise AssertionError(
            "composite alarm suppression state never converged within timeout",
        )

    assert composite["StateValue"] == "ALARM", f"expected composite StateValue ALARM, got {composite['StateValue']}"
    assert composite["ActionsSuppressedBy"] == "Alarm", (
        f"expected ActionsSuppressedBy 'Alarm' while suppressor is in ALARM, got {composite.get('ActionsSuppressedBy')!r}"
    )

    # Negative leg: a suppressor that is no longer in ALARM must stop being the suppression
    # reason. A stub that latches ActionsSuppressedBy=='Alarm' forever once the suppressor has
    # ever alarmed (rather than reading its *current* state) would pass everything above and
    # fail only here.
    cw.set_alarm_state(AlarmName=suppressor_name, StateValue="OK", StateReason="suppressor-cleared")

    # The suppressor leaving ALARM opens the extension period, during which the composite keeps
    # withholding actions under a DIFFERENT documented reason (ActionsSuppressorExtensionPeriod).
    # A stub that treats suppression as a single boolean -- 'Alarm' while the suppressor alarms,
    # cleared the instant it does not -- would pass a bare "no longer 'Alarm'" check without ever
    # rendering this phase, so it is asserted by its own name.
    extending = _poll_until(
        lambda: _get_composite(cw, composite_name),
        lambda c: c is not None and c.get("ActionsSuppressedBy") == "ExtensionPeriod",
        timeout_s=60.0,
    )
    if extending is None or extending.get("ActionsSuppressedBy") != "ExtensionPeriod":
        raise AssertionError(
            "composite alarm never reported ActionsSuppressedBy=='ExtensionPeriod' after the "
            f"suppressor left ALARM, got {extending.get('ActionsSuppressedBy') if extending else None!r}",
        )
    assert extending["StateValue"] == "ALARM", (
        f"expected composite StateValue ALARM during the extension period, got {extending['StateValue']!r}"
    )

    cleared = _poll_until(
        lambda: _get_composite(cw, composite_name),
        lambda c: c is not None and c.get("ActionsSuppressedBy") not in ("Alarm", "ExtensionPeriod"),
        timeout_s=180.0,
    )
    if cleared is None or cleared.get("ActionsSuppressedBy") in ("Alarm", "ExtensionPeriod"):
        raise AssertionError(
            "composite alarm kept withholding actions after its extension period should have elapsed",
        )
    assert cleared.get("ActionsSuppressedBy") not in ("Alarm", "ExtensionPeriod"), (
        f"expected ActionsSuppressedBy to clear after the extension period elapsed, got {cleared.get('ActionsSuppressedBy')!r}"
    )


def _get_composite(cw, alarm_name):
    alarms = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    return alarms[0] if alarms else None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
