"""health-check-failure-threshold-delays-status-flip."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "health-check-failure-threshold-delays-status-flip"
GROUP = "visibility-timeout-ttl"
SERVICES = ["route53"]


# timing:real-time — metric: 150 s
@tags("axis:happy-path", "cap:c4", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The CloudWatch HealthCheckStatus metric (1=healthy) for a new health check on an unreachable
    endpoint (a name under the reserved .invalid TLD, which never resolves) starts healthy and
    flips to 0 only after FailureThreshold failing probes."""
    route53 = ctx.client("route53")
    # GetHealthCheckStatus exposes only each checker's last raw probe, not the debounced
    # aggregate, so the CloudWatch metric is the signal for the threshold behaviour.
    cloudwatch = ctx.client("cloudwatch")

    # FailureThreshold * RequestInterval (in seconds) must comfortably exceed the
    # first 60s CloudWatch datapoint bucket, or the very first bucket could already
    # straddle the flip and make the "still healthy at first" assertion meaningless.
    failure_threshold = 5
    request_interval = 30

    health_check = route53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-hc-"),
        HealthCheckConfig={
            "FullyQualifiedDomainName": f"{ctx.unique_name('sim2real-hc').lower()}.invalid",
            "Port": 8081,
            "Type": "TCP",
            "RequestInterval": request_interval,
            "FailureThreshold": failure_threshold,
        },
    )
    hc_id = health_check["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_health_check(HealthCheckId=hc_id))

    deadline = time.monotonic() + 600.0

    points = _poll_for_datapoints(cloudwatch, hc_id, deadline)
    if not points:
        raise AssertionError(
            "no AWS/Route53 HealthCheckStatus CloudWatch datapoint landed within "
            "10 minutes of health-check creation -- this is a CloudWatch ingestion "
            "latency / metric-availability gap, not evidence either way about the "
            "threshold behavior; close by re-running with a longer window or "
            "confirming the metric namespace/region the target publishes to"
        )

    earliest = points[0]
    assert earliest["Minimum"] == 1.0, (
        "the very first HealthCheckStatus datapoint already reports unhealthy (0.0) "
        "even though FailureThreshold consecutive failing probes could not yet have "
        f"accumulated since health-check creation (threshold={failure_threshold}, "
        f"interval={request_interval}s)"
    )

    flipped = _poll_for_unhealthy(cloudwatch, hc_id, deadline)
    assert flipped, "HealthCheckStatus never flipped to unhealthy (0) for a permanently unreachable endpoint"


def _get_datapoints(cloudwatch, hc_id):
    resp = cloudwatch.get_metric_statistics(
        Namespace="AWS/Route53",
        MetricName="HealthCheckStatus",
        Dimensions=[{"Name": "HealthCheckId", "Value": hc_id}],
        StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=1200),
        EndTime=datetime.datetime.utcnow(),
        Period=60,
        Statistics=["Minimum"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


def _poll_for_datapoints(cloudwatch, hc_id, deadline):
    while time.monotonic() < deadline:
        points = _get_datapoints(cloudwatch, hc_id)
        if points:
            return points
        time.sleep(15.0)
    return []


def _poll_for_unhealthy(cloudwatch, hc_id, deadline):
    while time.monotonic() < deadline:
        points = _get_datapoints(cloudwatch, hc_id)
        if any(p["Minimum"] == 0.0 for p in points):
            return True
        time.sleep(15.0)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
