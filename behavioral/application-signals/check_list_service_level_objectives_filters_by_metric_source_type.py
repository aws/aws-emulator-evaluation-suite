"""list-service-level-objectives-filters-by-metric-source-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-service-level-objectives-filters-by-metric-source-type"
GROUP = "data-plane"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServiceLevelObjectives with MetricSourceTypes=[CloudWatchMetric] includes an SLO built on a
    custom CloudWatch metric and the summary's MetricSourceType reflects that."""
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

    matching = _list_all(sig, MetricSourceTypes=["CloudWatchMetric"])
    matching_names = {s["Name"] for s in matching}
    assert name in matching_names
    found = next(s for s in matching if s["Name"] == name)
    assert found["MetricSourceType"] == "CloudWatchMetric"

    non_matching = _list_all(sig, MetricSourceTypes=["ServiceOperation"])
    non_matching_names = {s["Name"] for s in non_matching}
    assert name not in non_matching_names


def _list_all(sig, **filters) -> list[dict]:
    out: list[dict] = []
    next_token = None
    while True:
        kwargs = dict(filters)
        if next_token:
            kwargs["NextToken"] = next_token
        resp = sig.list_service_level_objectives(**kwargs)
        out.extend(resp.get("SloSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


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
