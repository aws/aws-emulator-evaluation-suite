"""alarm-math-and-anomaly-search-and-undefined-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-math-and-anomaly-search-and-undefined-id-rejected"
GROUP = "metric-math-rejected"
SERVICES = ["cloudwatch"]

_SEARCH_MESSAGE = "SEARCH is not supported on Metric Alarms."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm refuses SEARCH() (bare or inside MAX()) and an undefined id with ValidationError
    and an exact message, creating nothing; a legal (m1/m2)*100 control alarm stays stored.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavSearchRej")
    control = ctx.unique_name("sim2real-behav-searchrej-ok-")

    def _stat(qid: str, metric: str) -> dict:
        return {"Id": qid, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": metric},
                                          "Period": 60, "Stat": "Maximum"}, "ReturnData": False}

    common = dict(Threshold=50.0, ComparisonOperator="GreaterThanThreshold", EvaluationPeriods=1,
                  ActionsEnabled=False, TreatMissingData="missing")
    search = f"SEARCH('{{{namespace}}} MetricName=\"Errors\"', 'Maximum', 60)"

    cw.put_metric_alarm(
        AlarmName=control,
        Metrics=[_stat("m1", "Errors"), _stat("m2", "Requests"),
                 {"Id": "e1", "Expression": "(m1/m2)*100", "ReturnData": True}],
        Tags=[{"Key": "sim2real", "Value": CHECK}], **common)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control]))
    assert len(_describe_all(cw, control)) == 1, f"the control alarm {control!r} was not stored"

    cases = [
        ("search-bare",
         [{"Id": "e1", "Expression": search, "Period": 60, "ReturnData": True}],
         lambda rid: _SEARCH_MESSAGE),
        ("search-wrapped",
         [{"Id": "s1", "Expression": search, "Period": 60, "ReturnData": False},
          {"Id": "e1", "Expression": "MAX(s1)", "ReturnData": True}],
         lambda rid: _SEARCH_MESSAGE),
        ("undefined-id",
         [_stat("m1", "Errors"), {"Id": "e1", "Expression": "(m1/m9)*100", "ReturnData": True}],
         # Real AWS embeds the request's own RequestId in this message.
         lambda rid: (
             "Error in expression 'e1': ID 'm9' not found (Service: AmazonCloudWatch; Status Code: "
             f"400; Error Code: ValidationException; Request ID: {rid}; Proxy: null)"
         )),
    ]
    for label, metrics, expected_message in cases:
        name = ctx.unique_name(f"sim2real-behav-searchrej-{label[:8]}-")
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        code, message, request_id = _error(lambda: cw.put_metric_alarm(AlarmName=name, Metrics=metrics,
                                                           **common),
                               subject=f"a {label} alarm expression")
        # The model declares only LimitExceededFault, but real AWS returns ValidationError (400).
        assert code == "ValidationError", (
            f"{label}: PutMetricAlarm raised {code!r} ({message!r}); real AWS raises "
            f"ValidationError"
        )
        expected = expected_message(request_id)
        assert message == expected, f"{label}: message {message!r}, expected {expected!r}"
        leaked = _describe_all(cw, name)
        assert leaked == [], f"{label}: the refused PutMetricAlarm created an alarm: {leaked!r}"

    assert len(_describe_all(cw, control)) == 1, (
        f"the control alarm {control!r} disappeared after the refusals"
    )


def _describe_all(cw, name):
    out = []
    for page in cw.get_paginator("describe_alarms").paginate(
            AlarmNames=[name], AlarmTypes=["MetricAlarm"]):
        out.extend(a for a in page.get("MetricAlarms", []) if a["AlarmName"] == name)
    return out


def _error(fn, *, subject: str) -> tuple[str, str, str]:
    """(code, message, request id) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""),
                exc.response.get("ResponseMetadata", {}).get("RequestId", ""))
    raise AssertionError(f"real AWS refuses {subject}, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
