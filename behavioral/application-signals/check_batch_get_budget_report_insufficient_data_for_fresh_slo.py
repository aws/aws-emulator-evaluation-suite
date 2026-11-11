"""batch-get-budget-report-insufficient-data-for-fresh-slo."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-budget-report-insufficient-data-for-fresh-slo"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created SLO with no attainment data yet reports BudgetStatus INSUFFICIENT_DATA."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    resp = sig.batch_get_service_level_objective_budget_report(
        Timestamp=dt.datetime.now(dt.timezone.utc),
        SloIds=[arn],
    )
    assert resp["Errors"] == [], f"expected no per-SLO errors, got {resp['Errors']!r}"
    assert len(resp["Reports"]) == 1, f"expected exactly 1 report, got {len(resp['Reports'])}"
    report = resp["Reports"][0]
    assert report["Arn"] == arn, f"expected report Arn {arn!r}, got {report['Arn']!r}"
    assert report["Name"] == name, f"expected report Name {name!r}, got {report['Name']!r}"
    assert report["BudgetStatus"] == "INSUFFICIENT_DATA", (
        f"expected BudgetStatus INSUFFICIENT_DATA for a fresh SLO with no attainment data, "
        f"got {report['BudgetStatus']!r}"
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
