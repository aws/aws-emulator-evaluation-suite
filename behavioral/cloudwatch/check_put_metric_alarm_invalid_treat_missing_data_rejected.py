"""put-metric-alarm-invalid-treat-missing-data-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-alarm-invalid-treat-missing-data-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm rejects an unsupported TreatMissingData value with
    ValidationError -- a distinct precondition from the statistic /
    extended-statistic combination checks."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-treatmissing-")

    error = None
    try:
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Statistic="Average",
            Period=300,
            EvaluationPeriods=1,
            Threshold=90.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="not-a-real-treatment",
        )
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
        raise AssertionError("real AWS rejects TreatMissingData='not-a-real-treatment', but the call SUCCEEDED")
    assert error["Code"] == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error["Message"] == (
        "The value not-a-real-treatment is not supported for TreatMissingData parameter. "
        "Supported values are [breaching, notBreaching, ignore, missing]."
    ), error["Message"]

    # Effect absent: the rejected alarm must not exist.
    resp = cw.describe_alarms(AlarmNames=[alarm_name])
    assert resp["MetricAlarms"] == [], resp["MetricAlarms"]

    # Positive control: same call with a valid TreatMissingData value succeeds
    # and persists exactly that value.
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    created = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(created) == 1, f"expected exactly one persisted alarm, got {created!r}"
    assert created[0]["TreatMissingData"] == "missing", created[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
