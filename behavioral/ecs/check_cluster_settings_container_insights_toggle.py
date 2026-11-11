"""cluster-settings-container-insights-toggle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-settings-container-insights-toggle"
GROUP = "state"
SERVICES = ["ecs"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateClusterSettings toggling containerInsights is reflected on subsequent DescribeClusters."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(
        clusterName=name,
        settings=[{"name": "containerInsights", "value": "disabled"}],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["cluster"]
    arn = cluster["clusterArn"]

    def _cleanup():
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    def _insights_value():
        described = ecs.describe_clusters(clusters=[arn], include=["SETTINGS"])["clusters"][0]
        settings = {s["name"]: s["value"] for s in described.get("settings", [])}
        return settings.get("containerInsights")

    value_at_creation = _insights_value()
    assert value_at_creation == "disabled", (
        f"expected containerInsights=disabled immediately after create_cluster, got {value_at_creation!r}"
    )

    ecs.update_cluster_settings(cluster=arn, settings=[{"name": "containerInsights", "value": "enabled"}])
    _poll_until(_insights_value, lambda v: v == "enabled", timeout_s=60.0, interval_s=2.0)
    assert _insights_value() == "enabled", "containerInsights setting did not flip to enabled"

    ecs.update_cluster_settings(cluster=arn, settings=[{"name": "containerInsights", "value": "disabled"}])
    _poll_until(_insights_value, lambda v: v == "disabled", timeout_s=60.0, interval_s=2.0)
    assert _insights_value() == "disabled", "containerInsights setting did not flip back to disabled"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
