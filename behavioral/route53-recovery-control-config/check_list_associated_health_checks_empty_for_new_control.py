"""list-associated-health-checks-empty-for-new-control."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-associated-health-checks-empty-for-new-control"
GROUP = "state"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """A new routing control lists no associated health checks; a RECOVERY_CONTROL health
    check mapped to it appears in the list and disappears once deleted, so an
    always-empty answer cannot pass."""
    client = ctx.client("route53-recovery-control-config")
    route53 = ctx.client("route53")

    cluster_arn = _get_or_create_shared_cluster(ctx, client)

    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn, ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-")
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_control_panel(ControlPanelArn=panel_arn)))

    rc_arn = client.create_routing_control(
        ClusterArn=cluster_arn,
        ControlPanelArn=panel_arn,
        RoutingControlName=ctx.unique_name("sim2real-r53arc-rc-"),
    )["RoutingControl"]["RoutingControlArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_routing_control(RoutingControlArn=rc_arn)))

    resp = client.list_associated_route53_health_checks(RoutingControlArn=rc_arn)
    assert resp["HealthCheckIds"] == [], (
        f"freshly created routing control must start with no associated health checks, "
        f"got {resp['HealthCheckIds']!r}"
    )

    # Real AWS rejects CreateHealthCheck(Type=RECOVERY_CONTROL) against a routing
    # control still in PENDING: "RoutingControlArn does not exist or is not
    # Deployed", so wait for DEPLOYED first.
    deadline = time.monotonic() + 180.0
    rc_status = None
    while time.monotonic() < deadline:
        rc_status = client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"]["Status"]
        if rc_status == "DEPLOYED":
            break
        time.sleep(5.0)
    assert rc_status == "DEPLOYED", f"routing control did not reach DEPLOYED in time (last: {rc_status!r})"

    hc_id = route53.create_health_check(
        CallerReference=f"sim2real-r53arc-hc-{uuid.uuid4()}",
        HealthCheckConfig={"Type": "RECOVERY_CONTROL", "RoutingControlArn": rc_arn},
    )["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: _delete_health_check(route53, hc_id))

    # The mapping is control-plane state a fresh health check must propagate into
    # before list_associated_route53_health_checks reflects it — bounded retry,
    # not a fixed wait.
    deadline = time.monotonic() + 60.0
    ids: list[str] = []
    while time.monotonic() < deadline:
        ids = client.list_associated_route53_health_checks(RoutingControlArn=rc_arn)["HealthCheckIds"]
        if hc_id in ids:
            break
        time.sleep(3.0)
    assert ids == [hc_id], (
        f"routing control must show exactly the health check mapped to it, "
        f"expected [{hc_id!r}], got {ids!r}"
    )

    route53.delete_health_check(HealthCheckId=hc_id)

    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        ids = client.list_associated_route53_health_checks(RoutingControlArn=rc_arn)["HealthCheckIds"]
        if hc_id not in ids:
            break
        time.sleep(3.0)
    assert hc_id not in ids, (
        f"deleting the mapped health check must remove the association, got {ids!r}"
    )


# ===== helpers =====
_SHARED_CLUSTER_NAME = "sim2real-behav-r53arc-shared"


def _get_or_create_shared_cluster(ctx, client):
    """Find-or-create a long-lived cluster shared across checks in this suite. The
    account's cluster quota is only 2, so most checks must NOT each create their own
    cluster; they share one DEPLOYED cluster (deleted in teardown by whichever check
    finds it holding nothing else) and only create/delete their
    own child resources (control panels, routing controls, safety rules) within it."""
    import time

    from botocore.exceptions import ClientError

    def _find():
        for page in client.get_paginator("list_clusters").paginate():
            for c in page["Clusters"]:
                if c["Name"] == _SHARED_CLUSTER_NAME and c["Status"] != "PENDING_DELETION":
                    return c["ClusterArn"]
        return None

    arn = _find()
    if arn is None:
        deadline = time.monotonic() + 250.0
        while arn is None:
            try:
                arn = client.create_cluster(ClusterName=_SHARED_CLUSTER_NAME)["Cluster"][
                    "ClusterArn"
                ]
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "ConflictException":
                    arn = _find()
                    if arn is None:
                        raise
                elif code == "ServiceQuotaExceededException" and time.monotonic() < deadline:
                    time.sleep(2.0)
                else:
                    raise


    ctx.on_cleanup(lambda: _delete_shared_cluster(client, arn))
    deadline = time.monotonic() + 420.0
    cluster = None
    while time.monotonic() < deadline:
        cluster = client.describe_cluster(ClusterArn=arn)["Cluster"]
        if cluster["Status"] == "DEPLOYED":
            return arn
        time.sleep(5.0)
    raise AssertionError(f"shared cluster did not reach DEPLOYED in time (last: {cluster!r})")


def _delete_health_check(route53, hc_id, timeout_s=60.0) -> None:
    """Delete the health check: NoSuchHealthCheck means gone, HealthCheckInUse retries every 2 s
    to the deadline, anything else raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            route53.delete_health_check(HealthCheckId=hc_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchHealthCheck":
                return
            if code != "HealthCheckInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
