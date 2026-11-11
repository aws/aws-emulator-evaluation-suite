"""slo-budget-report-reflects-goal-and-sli-fields."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slo-budget-report-reflects-goal-and-sli-fields"
GROUP = "data-plane"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetServiceLevelObjectiveBudgetReport echoes the exact Goal and RequestBasedSli
    configuration that was set on the SLO at creation time."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    goal = {
        "Interval": {"RollingInterval": {"DurationUnit": "DAY", "Duration": 3}},
        "AttainmentGoal": 95.0,
        "WarningThreshold": 30.0,
    }
    created = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Goal=goal,
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    created_goal = created["Goal"]
    assert created_goal["AttainmentGoal"] == 95.0, f"expected AttainmentGoal 95.0, got {created_goal['AttainmentGoal']}"
    assert created_goal["WarningThreshold"] == 30.0, f"expected WarningThreshold 30.0, got {created_goal['WarningThreshold']}"
    assert created_goal["Interval"]["RollingInterval"]["Duration"] == 3, (
        f"expected rolling interval Duration 3, got {created_goal['Interval']['RollingInterval']['Duration']}"
    )

    resp = sig.batch_get_service_level_objective_budget_report(
        Timestamp=dt.datetime.now(dt.timezone.utc),
        SloIds=[arn],
    )
    report = resp["Reports"][0]
    report_goal = report["Goal"]
    assert report_goal["AttainmentGoal"] == 95.0, f"expected AttainmentGoal 95.0, got {report_goal['AttainmentGoal']}"
    assert report_goal["WarningThreshold"] == 30.0, f"expected WarningThreshold 30.0, got {report_goal['WarningThreshold']}"
    assert report_goal["Interval"]["RollingInterval"]["Duration"] == 3, (
        f"expected rolling interval Duration 3, got {report_goal['Interval']['RollingInterval']['Duration']}"
    )
    assert report_goal["Interval"]["RollingInterval"]["DurationUnit"] == "DAY", (
        f"expected rolling interval DurationUnit DAY, got {report_goal['Interval']['RollingInterval']['DurationUnit']}"
    )
    assert report["EvaluationType"] == "RequestBased", f"expected EvaluationType RequestBased, got {report['EvaluationType']}"

    sli_metric = report["RequestBasedSli"]["RequestBasedSliMetric"]
    total_metric = sli_metric["TotalRequestCountMetric"][0]["MetricStat"]["Metric"]
    assert total_metric["Namespace"] == namespace, f"expected total-count Namespace {namespace}, got {total_metric['Namespace']}"
    assert total_metric["MetricName"] == metric_name, (
        f"expected total-count MetricName {metric_name}, got {total_metric['MetricName']}"
    )
    bad_metric = sli_metric["MonitoredRequestCountMetric"]["BadCountMetric"][0]["MetricStat"]["Metric"]
    expected_bad_name = f"{metric_name}Errors"
    assert bad_metric["MetricName"] == expected_bad_name, (
        f"expected bad-count MetricName {expected_bad_name}, got {bad_metric['MetricName']}"
    )


def _delete_slo_ignore_missing(sig, arn: str) -> None:
    try:
        sig.delete_service_level_objective(Id=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _request_based_sli_config(namespace: str, metric_name: str) -> dict:
    return {
        "RequestBasedSliMetricConfig": {
            "TotalRequestCountMetric": [
                {
                    "Id": "total",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Dimensions": [],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            "MonitoredRequestCountMetric": {
                "BadCountMetric": [
                    {
                        "Id": "bad",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": f"{metric_name}Errors",
                                "Dimensions": [],
                            },
                            "Period": 300,
                            "Stat": "Sum",
                        },
                        "ReturnData": True,
                    }
                ]
            },
        }
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
