"""put-metric-alarm-update-rejected-leaves-prior-config-untouched."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-alarm-update-rejected-leaves-prior-config-untouched"
GROUP = "alarm-config-rejected"
SERVICES = ["cloudwatch"]


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises.
    RAISES on success."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""),
                exc.response["ResponseMetadata"]["RequestId"])
    raise AssertionError(f"expected an AWS error, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An update whose Metrics expression names an undefined id is rejected with ValidationError and its
    exact message (which ends with the request's own id), leaving the stored Metrics and
    AlarmConfigurationUpdatedTimestamp unchanged; a well-formed update afterwards is applied."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealUpdateRejected")
    alarm_name = ctx.unique_name("sim2real-behav-cwupdrej-")

    def _stat(qid: str, metric: str) -> dict:
        return {
            "Id": qid,
            "MetricStat": {
                # DescribeAlarms always echoes an explicit empty Dimensions list, even though
                # none was submitted.
                "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": []},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        }

    def _describe() -> dict:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])
        assert len(alarms) == 1, f"expected exactly one alarm named {alarm_name!r}, got {alarms!r}"
        return alarms[0]

    good_metrics = [
        _stat("m1", "Errors"), _stat("m2", "Requests"),
        {"Id": "e1", "Expression": "m1 + m2", "Label": "Total", "ReturnData": True},
    ]
    common = dict(EvaluationPeriods=1, Threshold=100.0, ComparisonOperator="GreaterThanThreshold",
                  ActionsEnabled=False)

    # --- positive control: the valid shape is accepted as the alarm's first configuration -- #
    cw.put_metric_alarm(AlarmName=alarm_name, Metrics=good_metrics, **common)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    before = _describe()
    assert before["Metrics"] == good_metrics, (
        f"the positive-control alarm's Metrics were {before['Metrics']!r}, expected "
        f"{good_metrics!r}"
    )

    # --- negative: an update naming an undefined id in the Expression is rejected ---------- #
    broken_metrics = [
        good_metrics[0], good_metrics[1],
        {"Id": "e1", "Expression": "m1 + does_not_exist", "Label": "Broken", "ReturnData": True},
    ]
    code, message, request_id = _error(
        lambda: cw.put_metric_alarm(AlarmName=alarm_name, Metrics=broken_metrics, **common)
    )
    assert code == "ValidationError", (
        f"PutMetricAlarm with an Expression naming an undefined query id raised {code!r}, "
        f"expected ValidationError"
    )
    # Real AWS appends a backend trailer naming this request's own id to the message proper.
    want = (f"Error in expression 'e1': ID 'does_not_exist' not found (Service: AmazonCloudWatch; "
            f"Status Code: 400; Error Code: ValidationException; Request ID: {request_id}; "
            f"Proxy: null)")
    assert message == want, f"undefined-id refusal message {message!r}, expected {want!r}"

    # --- the rejected update left the PRIOR configuration exactly as it was --------------- #
    after = _describe()
    assert after["Metrics"] == good_metrics, (
        f"after the rejected update, Metrics were {after['Metrics']!r}; the prior, valid "
        f"configuration {good_metrics!r} must survive a rejected PutMetricAlarm untouched"
    )
    assert after["AlarmConfigurationUpdatedTimestamp"] == before["AlarmConfigurationUpdatedTimestamp"], (
        "a rejected PutMetricAlarm must not advance AlarmConfigurationUpdatedTimestamp"
    )

    # --- positive control: a well-formed update to the SAME alarm still succeeds ---------- #
    fixed_metrics = [
        good_metrics[0], good_metrics[1],
        {"Id": "e1", "Expression": "m1 * m2", "Label": "Product", "ReturnData": True},
    ]
    cw.put_metric_alarm(AlarmName=alarm_name, Metrics=fixed_metrics, **common)
    final = _describe()
    assert final["Metrics"] == fixed_metrics, (
        f"a well-formed update after the rejected one produced Metrics {final['Metrics']!r}, "
        f"expected {fixed_metrics!r} -- the rejection must not have wedged the alarm"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
