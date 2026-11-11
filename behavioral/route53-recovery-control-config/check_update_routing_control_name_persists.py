"""update-routing-control-name-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-routing-control-name-persists"
GROUP = "state"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """UpdateRoutingControl renames a routing control: Describe and List show the new name
    and the old one is freed; deleting the renamed control makes it unreachable by both
    a read and a mutation."""
    from botocore.exceptions import ClientError

    client = ctx.client("route53-recovery-control-config")

    cluster_arn = _get_or_create_shared_cluster(ctx, client)

    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn, ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-")
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_control_panel(ControlPanelArn=panel_arn)))

    old_name = ctx.unique_name("sim2real-r53arc-rc-old-")
    rc_arn = client.create_routing_control(
        ClusterArn=cluster_arn, ControlPanelArn=panel_arn, RoutingControlName=old_name
    )["RoutingControl"]["RoutingControlArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_routing_control(RoutingControlArn=rc_arn)))

    # UpdateRoutingControl rejects a routing control that hasn't finished its own
    # async provisioning yet (ValidationException: "not in DEPLOYED state"), so the
    # rename must wait for the same DEPLOYED transition the cluster already waits for.
    _wait_deployed(client, rc_arn)

    new_name = ctx.unique_name("sim2real-r53arc-rc-new-")
    updated = client.update_routing_control(RoutingControlArn=rc_arn, RoutingControlName=new_name)[
        "RoutingControl"
    ]
    assert updated["Name"] == new_name, (
        f"expected UpdateRoutingControl to echo the new name {new_name!r}, got {updated['Name']!r}"
    )

    described = client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"]
    assert described["Name"] == new_name, (
        f"expected DescribeRoutingControl to reflect the rename to {new_name!r}, got {described['Name']!r}"
    )

    listed = client.list_routing_controls(ControlPanelArn=panel_arn)["RoutingControls"]
    listed_names = [rc["Name"] for rc in listed]
    assert new_name in listed_names, (
        f"expected {new_name!r} in ListRoutingControls, got {listed_names!r}"
    )
    assert old_name not in listed_names, (
        f"expected the freed old name {old_name!r} to be absent, but ListRoutingControls returned {listed_names!r}"
    )

    # The rename itself re-triggers async provisioning (UpdateRoutingControl leaves
    # the control PENDING again), and DeleteRoutingControl demands DEPLOYED just as
    # UpdateRoutingControl did.
    _wait_deployed(client, rc_arn)

    client.delete_routing_control(RoutingControlArn=rc_arn)

    # DeleteRoutingControl doesn't remove the control synchronously either: it first
    # reads back as PENDING_DELETION before DescribeRoutingControl finally 404s.
    panel_id = panel_arn.rsplit("/", 1)[1]
    rc_id = rc_arn.rsplit("/", 1)[1]
    deadline = time.monotonic() + 180.0
    code = None
    message = None
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"][
                "Status"
            ]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
            break
        assert last_status == "PENDING_DELETION", (
            f"expected the deleted control to read back as PENDING_DELETION while its delete "
            f"settles, got {last_status!r}"
        )
        time.sleep(5.0)
    else:
        raise AssertionError(
            f"DescribeRoutingControl never raised NotFound within 180s of delete "
            f"(last status seen: {last_status!r})"
        )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeRoutingControl after delete, got {code}"
    )
    expected_message = (
        f"Routing control {panel_id}{rc_id} does not exist in control panel {panel_id}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    try:
        client.update_routing_control(
            RoutingControlArn=rc_arn, RoutingControlName=ctx.unique_name("sim2real-r53arc-rc-dead-")
        )
        raise AssertionError(
            "expected UpdateRoutingControl on the deleted control to fail with "
            "ResourceNotFoundException, but it SUCCEEDED"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from UpdateRoutingControl on a deleted control, got {code}"
        )
        message = err.response["Error"].get("Message")
        expected_message = f"{rc_id}not found in {panel_id}"
        assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


# ===== helpers =====
_SHARED_CLUSTER_NAME = "sim2real-behav-r53arc-shared"


def _get_or_create_shared_cluster(ctx, client):
    """Find-or-create a long-lived cluster shared across checks in this suite. The
    account's cluster quota is only 2, so most checks must NOT each create their own
    cluster; they share one DEPLOYED cluster (deleted in teardown by whichever check
    finds it holding nothing else) and only create/delete their
    own child resources (control panels, routing controls, safety rules) within it."""

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


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        pass


def _wait_deployed(client, rc_arn, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    rc = None
    while time.monotonic() < deadline:
        rc = client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"]
        if rc["Status"] == "DEPLOYED":
            return rc
        time.sleep(interval_s)
    raise AssertionError(f"routing control did not reach DEPLOYED in time (last: {rc!r})")


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
