"""list-routing-controls-pagination-next-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-routing-controls-pagination-next-token"
GROUP = "state"
SERVICES = ["route53-recovery-cluster"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """ListRoutingControls with MaxResults=1 pages through NextToken and returns each of
    three created routing controls exactly once, with no duplicates or omissions."""
    cfg = ctx.client("route53-recovery-control-config")

    cluster_arn, panel_arn = _get_or_create_shared_cluster(ctx, cfg)
    cluster = _cluster_data_client(ctx, cfg, cluster_arn)


    expected_arns = {
        _create_routing_control(ctx, cfg, cluster_arn, f"rc{i}")[1] for i in range(3)
    }

    seen_arns: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"ControlPanelArn": panel_arn, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cluster.list_routing_controls(**kwargs)
        page_arns = [rc["RoutingControlArn"] for rc in resp["RoutingControls"]]
        assert len(page_arns) <= 1, "MaxResults=1 must return at most one item per page"
        seen_arns.extend(page_arns)
        pages += 1
        next_token = resp.get("NextToken")
        if not next_token or pages > 20:
            break

    seen_for_our_controls = [arn for arn in seen_arns if arn in expected_arns]
    assert sorted(seen_for_our_controls) == sorted(expected_arns), (
        f"expected all 3 created routing controls to be paged over exactly once: "
        f"expected={sorted(expected_arns)} got={sorted(seen_for_our_controls)}"
    )
    assert len(seen_for_our_controls) == len(set(seen_for_our_controls)), "duplicate entries seen"


def _wait_cluster_deployed(cfg, cluster_arn, timeout_s=900.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfg.describe_cluster(ClusterArn=cluster_arn)["Cluster"]["Status"]
        if status == "DEPLOYED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached DEPLOYED (last status={status})")


def _wait_routing_control_deployed(cfg, rc_arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfg.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"]["Status"]
        if status == "DEPLOYED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"routing control never reached DEPLOYED (last status={status})")


_SHARED_CLUSTER_NAME = "sim2real-behav-r53arc-shared"


def _cluster_data_client(ctx, cfg, cluster_arn):
    """route53-recovery-cluster calls must target one of the cluster's 5 regional
    ClusterEndpoints -- there is no generic regional endpoint for this data plane."""
    endpoints = cfg.describe_cluster(ClusterArn=cluster_arn)["Cluster"]["ClusterEndpoints"]
    match = next((e for e in endpoints if e["Region"] == ctx.region), endpoints[0])
    return ctx.client("route53-recovery-cluster", endpoint_url=match["Endpoint"])


def _get_or_create_shared_cluster(ctx, cfg):
    """Reuse one ARC cluster across every check in this suite: real accounts are capped at
    2 concurrent clusters and a cluster takes several minutes to reach DEPLOYED, so each
    check provisioning (and tearing down) its own would blow both the per-check timeout and
    the account quota. Every check that uses it registers its teardown, and whichever finds it
    holding nothing else deletes it. Each check still creates and tears down
    its OWN routing control(s)/control panel/safety rule(s) inside it."""
    try:
        existing = [
            c
            for c in cfg.list_clusters().get("Clusters", [])
            if c.get("Name") == _SHARED_CLUSTER_NAME and c.get("Status") != "PENDING_DELETION"
        ]
    except ClientError:
        existing = []
    if existing:
        arn = existing[0]["ClusterArn"]
    else:
        try:
            arn = cfg.create_cluster(ClusterName=_SHARED_CLUSTER_NAME)["Cluster"]["ClusterArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                raise
            existing = [
                c
                for c in cfg.list_clusters().get("Clusters", [])
                if c.get("Name") == _SHARED_CLUSTER_NAME and c.get("Status") != "PENDING_DELETION"
            ]
            if not existing:
                raise
            arn = existing[0]["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_shared_cluster(cfg, arn))
    _wait_cluster_deployed(cfg, arn, timeout_s=250.0, interval_s=5.0)
    panel_arn = cfg.list_control_panels(ClusterArn=arn)["ControlPanels"][0]["ControlPanelArn"]
    return arn, panel_arn


def _create_routing_control(ctx, cfg, cluster_arn, prefix="rc"):
    name = ctx.unique_name(f"sim2real-{prefix}-")
    arn = cfg.create_routing_control(ClusterArn=cluster_arn, RoutingControlName=name)[
        "RoutingControl"
    ]["RoutingControlArn"]

    def _cleanup():
        _delete_own(lambda: cfg.delete_routing_control(RoutingControlArn=arn))

    ctx.on_cleanup(_cleanup)
    _wait_routing_control_deployed(cfg, arn)
    return name, arn


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
