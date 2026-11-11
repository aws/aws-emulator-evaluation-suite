"""slo-incompatible-sli-type-switch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slo-incompatible-sli-type-switch-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceLevelObjective switching a request-based SLO to a period-based SLI is rejected
    with ValidationException and the SLO keeps its request-based configuration, while an update
    of the same SLI type succeeds."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))
    assert created["EvaluationType"] == "RequestBased", (
        f"positive control: expected a freshly created request-based SLO to report "
        f"EvaluationType 'RequestBased', got {created['EvaluationType']!r}"
    )

    code, message = _client_error(
        lambda: sig.update_service_level_objective(
            Id=arn,
            SliConfig=_period_based_sli_config(namespace, metric_name),
        )
    )
    assert code == "ValidationException", (
        f"switching a request-based SLO to a period-based SliConfig: expected "
        f"ValidationException, got {code!r}"
    )
    assert message == "Updating from request-based SLO to period-based SLO is not allowed", (
        f"switching a request-based SLO to a period-based SliConfig: unexpected message {message!r}"
    )

    unchanged = sig.get_service_level_objective(Id=arn)["Slo"]
    assert unchanged["EvaluationType"] == "RequestBased", (
        f"the rejected type-switch changed EvaluationType to {unchanged['EvaluationType']!r}; "
        f"expected it to remain 'RequestBased'"
    )
    assert "RequestBasedSli" in unchanged, (
        f"the rejected type-switch dropped RequestBasedSli from the SLO: {sorted(unchanged)!r}"
    )

    compatible = sig.update_service_level_objective(
        Id=arn,
        Description="still request-based",
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
    )["Slo"]
    assert compatible["Description"] == "still request-based", (
        f"a same-type update was expected to succeed with the new description, its own "
        f"response showed {compatible['Description']!r}"
    )
    assert compatible["EvaluationType"] == "RequestBased", (
        f"a same-type update's own response showed EvaluationType="
        f"{compatible['EvaluationType']!r}, expected it to remain 'RequestBased'"
    )

    refetched = sig.get_service_level_objective(Id=arn)["Slo"]
    assert refetched["Description"] == "still request-based", (
        f"an independent read after the same-type update showed Description="
        f"{refetched['Description']!r}, expected 'still request-based'"
    )
    assert refetched["EvaluationType"] == "RequestBased", (
        f"an independent read after the same-type update showed EvaluationType="
        f"{refetched['EvaluationType']!r}, expected 'RequestBased'"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so
    accepting input AWS refuses never reads as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
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


def _period_based_sli_config(namespace: str, metric_name: str) -> dict:
    return {
        "SliMetricConfig": {
            "MetricDataQueries": [
                {
                    "Id": "value",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Dimensions": [],
                        },
                        "Period": 300,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                }
            ],
        },
        "MetricThreshold": 500.0,
        "ComparisonOperator": "LessThan",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
