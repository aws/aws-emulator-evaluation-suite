"""describe-alarm-contributors-nonexistent-composite-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-nonexistent-composite-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmContributors fails with ResourceNotFoundException "No alarm for name <name> was
    found" for a name that never existed, and with ValidationError "Alarm <name> is not a multi time
    series alarm" for an existing ordinary metric alarm."""
    cw = ctx.client("cloudwatch")

    missing_name = ctx.unique_name("sim2real-dac-missing-")
    code, message = _client_error(lambda: cw.describe_alarm_contributors(AlarmName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for missing alarm, got {code}"
    expected_missing = f"No alarm for name {missing_name} was found"
    assert message == expected_missing, f"expected message {expected_missing!r}, got {message!r}"

    ordinary_alarm = ctx.unique_name("sim2real-dac-ordinary-")
    cw.put_metric_alarm(
        AlarmName=ordinary_alarm,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="sim2real-dac-metric",
        Namespace="Sim2RealBehavioral",
        Period=60,
        Statistic="Average",
        Threshold=100.0,
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ordinary_alarm]))

    # The alarm genuinely exists (positive control) -- it is the wrong type, not absent.
    described = cw.describe_alarms(AlarmNames=[ordinary_alarm])
    assert len(described["MetricAlarms"]) == 1, "sanity: the ordinary metric alarm must exist"

    code2, message2 = _client_error(lambda: cw.describe_alarm_contributors(AlarmName=ordinary_alarm))
    assert code2 == "ValidationError", (
        f"expected ValidationError for a non-multi-timeseries alarm, got {code2}"
    )
    expected_message = f"Alarm {ordinary_alarm} is not a multi time series alarm"
    assert message2 == expected_message, f"expected message {expected_message!r}, got {message2!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an emulator
    accepting a call AWS refuses is never reported as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
