"""aws-network-performance-data-matches-subscription."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "aws-network-performance-data-matches-subscription"
GROUP = "telemetry"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ec2-network-performance-subscription")
def run(ctx) -> None:
    """After EnableAwsNetworkPerformanceMetricSubscription, one GetAwsNetworkPerformanceData call for two Region
    pairs answers each query with its own Source, Destination, metric aggregate-latency and statistic p50, and
    the two pairs' MetricPoints differ.
    """
    ec2 = ctx.client("ec2")

    source = ctx.region
    dest_a, dest_b = _pick_two_other_regions(ctx, exclude=source)

    # A pair the account already subscribes is used as is and left subscribed.
    subscribed = {
        s["Destination"]
        for s in ec2.describe_aws_network_performance_metric_subscriptions()["Subscriptions"]
        if s["Source"] == source and s["Metric"] == "aggregate-latency" and s["Statistic"] == "p50"
    }
    for dest in (dest_a, dest_b):
        if dest in subscribed:
            continue
        ec2.enable_aws_network_performance_metric_subscription(
            Source=source, Destination=dest, Metric="aggregate-latency", Statistic="p50"
        )
        ctx.on_cleanup(
            lambda dest=dest: ec2.disable_aws_network_performance_metric_subscription(
                Source=source, Destination=dest, Metric="aggregate-latency", Statistic="p50"
            )
        )

    now = dt.datetime.now(dt.timezone.utc)
    query_a = {
        "Id": "sim2real-q-a",
        "Source": source,
        "Destination": dest_a,
        "Metric": "aggregate-latency",
        "Statistic": "p50",
        "Period": "five-minutes",
    }
    query_b = {
        "Id": "sim2real-q-b",
        "Source": source,
        "Destination": dest_b,
        "Metric": "aggregate-latency",
        "Statistic": "p50",
        "Period": "five-minutes",
    }

    def _fetch() -> dict:
        resp = ec2.get_aws_network_performance_data(
            DataQueries=[query_a, query_b],
            StartTime=now - dt.timedelta(hours=6),
            EndTime=now,
        )
        return {r["Id"]: r for r in resp["DataResponses"]}

    by_id: dict = {}
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        by_id = _fetch()
        if by_id.get("sim2real-q-a", {}).get("MetricPoints") and by_id.get("sim2real-q-b", {}).get(
            "MetricPoints"
        ):
            break
        time.sleep(2)

    if "sim2real-q-a" not in by_id or "sim2real-q-b" not in by_id:
        raise AssertionError(
            "GetAwsNetworkPerformanceData did not return a DataResponse for both queried pairs "
            f"{source}->{dest_a} and {source}->{dest_b}: got ids {sorted(by_id)}"
        )
    response_a, response_b = by_id["sim2real-q-a"], by_id["sim2real-q-b"]

    # Scoping: each response matches exactly the pair it was queried for -- never swapped.
    assert response_a["Source"] == source and response_a["Destination"] == dest_a, response_a
    assert response_b["Source"] == source and response_b["Destination"] == dest_b, response_b
    assert response_a["Metric"] == "aggregate-latency" and response_a["Statistic"] == "p50"
    assert response_b["Metric"] == "aggregate-latency" and response_b["Statistic"] == "p50"

    if not response_a.get("MetricPoints"):
        raise AssertionError(
            f"no aggregate-latency datapoints published yet for {source}->{dest_a} "
            "within the queried window"
        )
    if not response_b.get("MetricPoints"):
        raise AssertionError(
            f"no aggregate-latency datapoints published yet for {source}->{dest_b} "
            "within the queried window"
        )

    # Cross-pair isolation: the two DIFFERENT pairs queried in the SAME call must not
    # return each other's data -- a target that ignores Source/Destination and answers
    # every query with the same series would pass every assertion above and only fail here.
    assert response_a["MetricPoints"] != response_b["MetricPoints"], (
        f"{source}->{dest_a} and {source}->{dest_b} returned identical MetricPoints; "
        "GetAwsNetworkPerformanceData is not scoping data by Region pair"
    )


def _pick_two_other_regions(ctx, exclude: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    regions = [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=False)["Regions"]
        if r["RegionName"] != exclude
    ]
    if len(regions) < 2:
        raise AssertionError(
            "fewer than two other enabled Regions available to form two source/destination pairs"
        )
    # Prefer well-known, always-on Regions if present, for stable latency data.
    preferred = [r for r in ("us-east-1", "us-west-2", "eu-west-1") if r in regions]
    ordered = preferred + sorted(r for r in regions if r not in preferred)
    return ordered[0], ordered[1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
