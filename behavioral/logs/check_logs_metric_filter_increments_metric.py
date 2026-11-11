"""logs-metric-filter-increments-metric."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


CHECK = "logs-metric-filter-increments-metric"
GROUP = 'data-plane'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A metric filter on a log group publishes its metric, and GetMetricStatistics reaches a Sum of 2
    after two matching events are written.
    """
    svc = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group = ctx.unique_name("sim2real-behav-/lg-mf-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    stream = "s1"
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    namespace = ctx.unique_name("sim2real-behav-mf-ns-")
    metric_name = "MatchCount"
    filter_name = ctx.unique_name("sim2real-behav-mf-")
    svc.put_metric_filter(
        logGroupName=group,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "1",
                "defaultValue": 0.0,
            }
        ],
    )

    now = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": now, "message": "ERROR first failure"},
            {"timestamp": now + 1, "message": "ERROR second failure"},
            {"timestamp": now + 2, "message": "INFO ignored"},
        ],
    )

    def metric_sum():
        end = datetime.now(timezone.utc) + timedelta(minutes=1)
        start = end - timedelta(minutes=20)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum"],
        )
        return sum(d.get("Sum", 0.0) for d in resp.get("Datapoints", []))

    total = _poll_until(
        metric_sum,
        lambda s: s >= 2,
        timeout_s=300,
        interval_s=15,
        description="metric filter incrementing the extracted metric",
    )
    assert total == 2, (
        f"expected extracted metric Sum == 2 (one per matching ERROR event, defaultValue=0.0 for "
        f"the non-matching INFO event), got {total} -- a filter that fires on every event "
        f"regardless of pattern would report 3"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
