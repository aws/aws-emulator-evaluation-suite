"""routing-control-state-toggle-via-recovery-cluster-data-plane."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "routing-control-state-toggle-via-recovery-cluster-data-plane"
GROUP = "cross-service"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """A routing control created through the config plane reads Off on the cluster data plane, and
    UpdateRoutingControlState there flips it On and back Off, as GetRoutingControlState reads back.
    """
    config = ctx.client("route53-recovery-control-config")

    # Real accounts are capped at 2 concurrent ARC clusters, and a cluster takes several
    # minutes to reach DEPLOYED, so a check that provisions (and tears down) its own would
    # blow both the account quota and the per-check timeout. Reuse one cluster across every
    # check that needs one: every check that uses it registers its teardown, and whichever finds
    # it holding nothing else deletes it.
    cluster_arn, panel_arn = _get_or_create_shared_cluster(ctx, config)

    cluster = config.describe_cluster(ClusterArn=cluster_arn)["Cluster"]
    # route53-recovery-cluster has no generic regional endpoint -- calls must target one of the
    # cluster's own ClusterEndpoints (real AWS refuses to resolve
    # route53-recovery-cluster.<region>.amazonaws.com at all: EndpointConnectionError).
    cluster_client = _cluster_data_client(ctx, cluster)

    rc_arn = config.create_routing_control(
        ClusterArn=cluster_arn,
        ControlPanelArn=panel_arn,
        RoutingControlName=ctx.unique_name("sim2real-r53arc-rc-"),
    )["RoutingControl"]["RoutingControlArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: config.delete_routing_control(RoutingControlArn=rc_arn)))

    _poll_until(
        probe=lambda: config.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"][
            "Status"
        ],
        predicate=lambda status: status == "DEPLOYED",
        timeout_s=180.0,
        interval_s=5.0,
    )

    initial_state = _poll_until(
        probe=lambda: cluster_client.get_routing_control_state(RoutingControlArn=rc_arn)[
            "RoutingControlState"
        ],
        predicate=lambda state: state in ("On", "Off"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert initial_state == "Off", initial_state

    cluster_client.update_routing_control_state(RoutingControlArn=rc_arn, RoutingControlState="On")

    on_state = _poll_until(
        probe=lambda: cluster_client.get_routing_control_state(RoutingControlArn=rc_arn)[
            "RoutingControlState"
        ],
        predicate=lambda state: state == "On",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert on_state == "On", on_state

    cluster_client.update_routing_control_state(RoutingControlArn=rc_arn, RoutingControlState="Off")

    off_state = _poll_until(
        probe=lambda: cluster_client.get_routing_control_state(RoutingControlArn=rc_arn)[
            "RoutingControlState"
        ],
        predicate=lambda state: state == "Off",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert off_state == "Off", off_state


_SHARED_CLUSTER_NAME = "sim2real-behav-r53arc-shared"


def _get_or_create_shared_cluster(ctx, config):
    from botocore.exceptions import ClientError

    try:
        existing = [
            c
            for c in config.list_clusters().get("Clusters", [])
            if c.get("Name") == _SHARED_CLUSTER_NAME and c.get("Status") != "PENDING_DELETION"
        ]
    except ClientError:
        existing = []
    if existing:
        arn = existing[0]["ClusterArn"]
    else:
        try:
            arn = config.create_cluster(
                ClusterName=_SHARED_CLUSTER_NAME, Tags={"sim2real": "behavioral"}
            )["Cluster"]["ClusterArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                raise
            existing = [
                c
                for c in config.list_clusters().get("Clusters", [])
                if c.get("Name") == _SHARED_CLUSTER_NAME and c.get("Status") != "PENDING_DELETION"
            ]
            if not existing:
                raise
            arn = existing[0]["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_shared_cluster(config, arn))
    _poll_until(
        probe=lambda: config.describe_cluster(ClusterArn=arn)["Cluster"]["Status"],
        predicate=lambda status: status == "DEPLOYED",
        timeout_s=420.0,
        interval_s=5.0,
    )
    panel_arn = config.list_control_panels(ClusterArn=arn)["ControlPanels"][0]["ControlPanelArn"]
    return arn, panel_arn


def _cluster_data_client(ctx, cluster):
    endpoints = cluster["ClusterEndpoints"]
    match = next((e for e in endpoints if e["Region"] == ctx.region), endpoints[0])
    return ctx.client("route53-recovery-cluster", endpoint_url=match["Endpoint"])


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        pass


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


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


def _delete_shared_cluster(client, arn, timeout_s=600.0, interval_s=5.0) -> None:
    """Teardown for the shared cluster, registered by every check that uses it: a cluster bills by
    the hour, so it must never be left without an owner. The check's own cleanups have already
    deleted its control panels, routing controls and safety rules. This waits, within a bounded
    window, until the cluster holds no non-default control panel and no routing control other
    than ones being deleted, then deletes the cluster and waits until it is gone; it deletes
    nothing else. A non-default control panel or a live routing control still there after 60 s
    belongs to another check, whose own teardown deletes the cluster; this teardown then raises
    naming what holds the cluster, so the check's cleanup detail reports it."""
    import time

    from botocore.exceptions import ClientError

    def _holders():
        held, deleting = [], []
        for page in client.get_paginator("list_control_panels").paginate(ClusterArn=arn):
            for panel in page.get("ControlPanels", []):
                if not panel.get("DefaultControlPanel"):
                    side = deleting if panel.get("Status") == "PENDING_DELETION" else held
                    side.append(panel["ControlPanelArn"])
                    continue
                rcs = client.get_paginator("list_routing_controls").paginate(
                    ControlPanelArn=panel["ControlPanelArn"]
                )
                for rc_page in rcs:
                    for rc in rc_page.get("RoutingControls", []):
                        side = deleting if rc.get("Status") == "PENDING_DELETION" else held
                        side.append(rc["RoutingControlArn"])
        return held, deleting

    deadline = time.monotonic() + timeout_s
    held_until = time.monotonic() + 60.0
    while True:
        try:
            held, deleting = _holders()
            if held and time.monotonic() >= held_until:
                raise AssertionError(
                    f"shared cluster {arn} left in place for the check that holds it: "
                    f"{len(held)} control panel(s)/routing control(s) not created by this check "
                    f"remain: {held}"
                )
            if not held and not deleting:
                client.delete_cluster(ClusterArn=arn)
                break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"shared cluster {arn} not deleted: children still deleting after {timeout_s}s: "
                f"{deleting}"
            )
        time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"shared cluster {arn} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
