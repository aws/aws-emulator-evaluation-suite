"""cluster-and-routing-control-reach-deployed-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cluster-and-routing-control-reach-deployed-status"
GROUP = "state"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """A new cluster transitions PENDING->DEPLOYED with 5 endpoints, auto-creates a
    default control panel, and a routing control created on it also reaches DEPLOYED."""
    client = ctx.client("route53-recovery-control-config")

    cluster_name = ctx.unique_name("sim2real-r53arc-cluster-")
    cluster_arn = _create_cluster_with_retry(client, cluster_name)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(client, cluster_arn))

    cluster = _poll_until(
        probe=lambda: client.describe_cluster(ClusterArn=cluster_arn)["Cluster"],
        predicate=lambda c: c["Status"] == "DEPLOYED",
        timeout_s=200.0,
        interval_s=5.0,
    )
    assert cluster["Status"] == "DEPLOYED", f"cluster stuck at {cluster['Status']!r}"
    assert len(cluster["ClusterEndpoints"]) == 5, cluster["ClusterEndpoints"]

    # cluster creation auto-creates exactly one default control panel
    panels = client.list_control_panels(ClusterArn=cluster_arn)["ControlPanels"]
    default_panels = [p for p in panels if p["DefaultControlPanel"]]
    assert len(default_panels) == 1, panels
    assert default_panels[0]["RoutingControlCount"] == 0, (
        f"expected 0 routing controls on fresh default panel, got "
        f"{default_panels[0]['RoutingControlCount']}"
    )

    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn,
        ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-"),
        Tags={"sim2real": CHECK},
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_control_panel(ControlPanelArn=panel_arn)))

    rc_arn = client.create_routing_control(
        ClusterArn=cluster_arn,
        ControlPanelArn=panel_arn,
        RoutingControlName=ctx.unique_name("sim2real-r53arc-rc-"),
    )["RoutingControl"]["RoutingControlArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_routing_control(RoutingControlArn=rc_arn)))

    rc = _poll_until(
        probe=lambda: client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"],
        predicate=lambda r: r["Status"] == "DEPLOYED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert rc["Status"] == "DEPLOYED", f"routing control stuck at {rc['Status']!r}"


def _create_cluster_with_retry(client, name, timeout_s=60.0, interval_s=10.0):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window: the
    account's 2-cluster quota may still be draining an async delete from a prior check's
    teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_cluster(ClusterName=name, Tags={"sim2real": CHECK})["Cluster"][
                "ClusterArn"
            ]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_own(delete, timeout_s=300.0, interval_s=5.0) -> None:
    """Teardown: delete one resource this check created. A refusal while the resource's own
    children are still deleting (ConflictException, ValidationException) is retried; not found
    is success; a timeout or any other error raises, so nothing of the check's is left silently."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_cluster_and_wait(client, cluster_arn, timeout_s=300.0, interval_s=5.0) -> None:
    """Teardown: delete the cluster this check created and block until it is gone. The account's
    cluster quota (2) is freed only once deletion completes, so the next check that needs a
    cluster can create one. A refusal while the cluster's own children are still deleting is
    retried; not found is success; any other error, or a cluster still present at the deadline,
    raises."""
    import time

    from botocore.exceptions import ClientError

    _delete_own(lambda: client.delete_cluster(ClusterArn=cluster_arn), timeout_s, interval_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
