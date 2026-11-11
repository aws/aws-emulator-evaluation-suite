"""slo-update-persists-fields-and-advances-timestamp."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slo-update-persists-fields-and-advances-timestamp"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceLevelObjective persists new fields, keeps CreatedTime, and advances LastUpdatedTime."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        Description="initial description",
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    created_time = created["CreatedTime"]
    initial_updated_time = created["LastUpdatedTime"]

    # Re-issue the same update (idempotent on content) until the server-side clock ticks past
    # the original LastUpdatedTime, instead of sleeping a fixed duration and hoping it was enough.
    updated = _poll_until(
        lambda: sig.update_service_level_objective(
            Id=arn,
            Description="updated description",
        )["Slo"],
        lambda slo: slo["LastUpdatedTime"] > initial_updated_time,
        timeout_s=30,
        interval_s=2,
    )

    assert updated["Description"] == "updated description", (
        f"expected Description='updated description' on the update response, got {updated['Description']!r}"
    )
    assert updated["CreatedTime"] == created_time, (
        f"expected CreatedTime to survive the update unchanged at {created_time!r}, "
        f"got {updated['CreatedTime']!r}"
    )
    assert updated["LastUpdatedTime"] > initial_updated_time, (
        f"expected LastUpdatedTime to advance past {initial_updated_time!r}, "
        f"got {updated['LastUpdatedTime']!r}"
    )

    refetched = sig.get_service_level_objective(Id=arn)["Slo"]
    assert refetched["Description"] == "updated description", (
        f"expected the independent GetServiceLevelObjective read to see Description='updated description', "
        f"got {refetched['Description']!r}"
    )
    assert refetched["LastUpdatedTime"] == updated["LastUpdatedTime"], (
        f"expected the independent read's LastUpdatedTime to match the update response "
        f"({updated['LastUpdatedTime']!r}), got {refetched['LastUpdatedTime']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s; last value={last!r}")


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
