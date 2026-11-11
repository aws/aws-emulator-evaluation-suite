"""delete-alarm-referenced-by-composite-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-alarm-referenced-by-composite-conflict"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

#: Bounded convergence for alarm visibility, sized from the default service-class budget.
_CONVERGE_WAIT_S = 120

def _error(fn):
    """Call fn(); return the botocore (Code, Message, HTTP status). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return error.get("Code"), error.get("Message"), status
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on an alarm referenced by a composite alarm's AlarmRule must fail while the
    reference holds, must leave the alarm intact, and the identical call must succeed once the
    composite alarm is removed (overly-permissive check)."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-behav-cwprobe-child-")
    composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    tags_kv = [{"Key": "sim2real", "Value": CHECK}]
    ctx.on_cleanup(lambda _n=child_name: cw.delete_alarms(AlarmNames=[_n]))
    ctx.on_cleanup(lambda _n=composite_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=tags_kv,
    )
    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        Tags=tags_kv,
    )

    def probe_composite():
        return cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])

    _poll_until(probe_composite, lambda r: len(r.get("CompositeAlarms", [])) > 0, timeout_s=_CONVERGE_WAIT_S, interval_s=2)

    def delete_child():
        return cw.delete_alarms(AlarmNames=[child_name])

    code, message, status = _error(delete_child)
    assert code == "ValidationError", (
        f"expected ValidationError deleting an alarm referenced by a composite alarm, got {code}"
    )
    assert status == 400, f"expected HTTP 400 for the refused delete, got {status!r}"
    expected_message = f"Cannot delete {child_name} as there are composite alarm(s) depending on it."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    still_there = cw.describe_alarms(AlarmNames=[child_name], AlarmTypes=["MetricAlarm"]).get("MetricAlarms", [])
    assert len(still_there) == 1, f"child alarm should still exist after the rejected delete, got {still_there}"

    cw.delete_alarms(AlarmNames=[composite_name])

    def probe_composite_gone():
        return cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"]).get(
            "CompositeAlarms", []
        )

    _poll_until(
        probe_composite_gone,
        lambda r: len(r) == 0,
        timeout_s=_CONVERGE_WAIT_S,
        interval_s=2,
        description="composite alarm deletion visible",
    )

    # The identical delete succeeds once the reference is removed; a rejection raises here.
    delete_child()

    gone = cw.describe_alarms(AlarmNames=[child_name], AlarmTypes=["MetricAlarm"]).get("MetricAlarms", [])
    assert gone == [], f"child alarm should be gone after the now-permitted delete, got {gone}"

    # The deleted child is unusable, not just unlisted.
    code, message, status = _error(
        lambda: cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason="dead")
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound on the deleted alarm, got {code!r}"
    assert status == 404, f"expected HTTP 404 on the deleted alarm, got {status!r}"
    expected_message = ""
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    # CloudWatch sends this ResourceNotFound with an empty message.


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
