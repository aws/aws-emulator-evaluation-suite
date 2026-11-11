"""alarm-math-and-anomaly-return-data-count-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-math-and-anomaly-return-data-count-rejected"
GROUP = "metric-math-rejected"
SERVICES = ["cloudwatch"]

_MESSAGE = "Exactly one element of the metrics list should return data."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm whose Metrics array has zero or two ReturnData=True members fails with
    ValidationError "Exactly one element of the metrics list should return data." and creates no
    alarm; the same array with only the expression returning is stored and stays unchanged."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavRdCount")
    control = ctx.unique_name("sim2real-behav-rdcount-ok-")

    def _stat(qid: str, metric: str, rd: bool) -> dict:
        return {"Id": qid, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": metric},
                                          "Period": 60, "Stat": "Maximum"}, "ReturnData": rd}

    def _arr(m1: bool, e1: bool, extra: bool | None = None) -> list[dict]:
        arr = [_stat("m1", "Errors", m1), _stat("m2", "Requests", False),
               {"Id": "e1", "Expression": "(m1/m2)*100", "ReturnData": e1}]
        if extra is not None:
            arr.append({"Id": "e2", "Expression": "m1*2", "ReturnData": extra})
        return arr

    common = dict(Threshold=50.0, ComparisonOperator="GreaterThanThreshold", EvaluationPeriods=1,
                  ActionsEnabled=False, TreatMissingData="missing")

    # --- positive control: exactly one returning member is accepted ------------------------------ #
    cw.put_metric_alarm(AlarmName=control, Metrics=_arr(False, True), **common,
                        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control]))
    stored = _describe_all(cw, control)
    assert len(stored) == 1, f"the control alarm {control!r} is not stored: {stored!r}"
    returning = [q["Id"] for q in stored[0]["Metrics"] if q.get("ReturnData")]
    assert returning == ["e1"], (
        f"the control alarm reads back returning members {returning!r}; expected ['e1']"
    )

    cases = {
        "zero-returning": _arr(False, False),
        "metricstat-and-expression-returning": _arr(True, True),
        "two-expressions-returning": _arr(False, True, extra=True),
    }
    for label, arr in cases.items():
        name = ctx.unique_name(f"sim2real-behav-rdcount-{label[:10]}-")
        # Registered BEFORE the call: if a target wrongly accepts, the alarm exists.
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        code, message = _error(lambda: cw.put_metric_alarm(AlarmName=name, Metrics=arr, **common),
                               subject=f"a Metrics array with {label} members")
        assert code == "ValidationError", (
            f"{label}: PutMetricAlarm raised {code!r} ({message!r}); real AWS raises "
            f"ValidationError"
        )
        assert message == _MESSAGE, (
            f"{label}: the refusal message is {message!r}; real AWS says {_MESSAGE!r}"
        )
        leaked = _describe_all(cw, name)
        assert leaked == [], f"{label}: the refused PutMetricAlarm created an alarm: {leaked!r}"

    # the control is untouched by the refusals
    after = _describe_all(cw, control)
    assert len(after) == 1 and [q["Id"] for q in after[0]["Metrics"] if q.get("ReturnData")] == [
        "e1"], f"the control alarm changed after the refusals: {after!r}"


def _describe_all(cw, name):
    out = []
    for page in cw.get_paginator("describe_alarms").paginate(
            AlarmNames=[name], AlarmTypes=["MetricAlarm"]):
        out.extend(a for a in page.get("MetricAlarms", []) if a["AlarmName"] == name)
    return out


def _error(fn, *, subject: str) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS refuses {subject}, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
