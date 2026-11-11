"""delete-cluster-with-dependents-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-cluster-with-dependents-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """DeleteCluster on a DEPLOYED cluster that still holds a control panel and routing
    control is rejected with ValidationException (not ConflictException) and leaves all
    three intact; deleting the dependents first lets the cluster deletion succeed."""
    client = ctx.client("route53-recovery-control-config")

    cluster_arn = _create_cluster_with_retry(client, ctx.unique_name("sim2real-r53arc-cluster-"))
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(client, cluster_arn))
    # wait for the cluster to actually deploy before testing the dependents contract,
    # so a still-PENDING tree can never be mistaken for the rejection under test.
    _poll_until(
        probe=lambda: client.describe_cluster(ClusterArn=cluster_arn)["Cluster"]["Status"],
        predicate=lambda status: status == "DEPLOYED",
        timeout_s=200.0,
        interval_s=5.0,
    )
    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn, ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-")
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: client.delete_control_panel(ControlPanelArn=panel_arn)))
    rc_arn = client.create_routing_control(
        ClusterArn=cluster_arn,
        ControlPanelArn=panel_arn,
        RoutingControlName=ctx.unique_name("sim2real-r53arc-rc-"),
    )["RoutingControl"]["RoutingControlArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: client.delete_routing_control(RoutingControlArn=rc_arn)))
    _poll_until(
        probe=lambda: client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"][
            "Status"
        ],
        predicate=lambda status: status == "DEPLOYED",
        timeout_s=180.0,
        interval_s=5.0,
    )

    code, message = _error(lambda: client.delete_cluster(ClusterArn=cluster_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Cannot delete a Cluster with non-default Control Panels.", message

    # effect is absent: cluster, control panel and routing control all still exist
    found_cluster_arn = client.describe_cluster(ClusterArn=cluster_arn)["Cluster"]["ClusterArn"]
    assert found_cluster_arn == cluster_arn, (
        f"cluster should survive the rejected delete: expected {cluster_arn!r}, "
        f"got {found_cluster_arn!r}"
    )
    found_panel_arn = client.describe_control_panel(ControlPanelArn=panel_arn)["ControlPanel"][
        "ControlPanelArn"
    ]
    assert found_panel_arn == panel_arn, (
        f"control panel should survive the rejected delete: expected {panel_arn!r}, "
        f"got {found_panel_arn!r}"
    )
    found_rc_arn = client.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"][
        "RoutingControlArn"
    ]
    assert found_rc_arn == rc_arn, (
        f"routing control should survive the rejected delete: expected {rc_arn!r}, "
        f"got {found_rc_arn!r}"
    )

    # positive control: remove dependents first, then delete succeeds. Each delete is
    # itself async — the parent's own delete rejects with "non-empty"/dependents-exist
    # until the child delete has actually propagated, not merely returned — so each
    # step is confirmed gone via an independent read before the next is attempted.
    client.delete_routing_control(RoutingControlArn=rc_arn)
    _poll_until(
        probe=lambda: _gone(lambda: client.describe_routing_control(RoutingControlArn=rc_arn)),
        predicate=bool,
        timeout_s=120.0,
        interval_s=3.0,
    )
    client.delete_control_panel(ControlPanelArn=panel_arn)
    _poll_until(
        probe=lambda: _gone(lambda: client.describe_control_panel(ControlPanelArn=panel_arn)),
        predicate=bool,
        timeout_s=120.0,
        interval_s=3.0,
    )
    client.delete_cluster(ClusterArn=cluster_arn)
    _poll_until(
        probe=lambda: _gone(lambda: client.describe_cluster(ClusterArn=cluster_arn)),
        predicate=bool,
        timeout_s=120.0,
        interval_s=3.0,
    )


# ===== helpers =====
def _create_cluster_with_retry(client, name, timeout_s=900.0, interval_s=15.0):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window —
    the account's 2-cluster quota may still be draining an async delete from a
    prior check's teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_cluster(ClusterName=name)["Cluster"]["ClusterArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_cluster_with_retry(client, cluster_arn, timeout_s=240.0, interval_s=2.0) -> None:
    """Cleanup-path DeleteCluster: retries the Conflict/Validation refusal while the routing
    control and control panel deletes are still propagating; not found is success, a
    timeout or any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_cluster(ClusterArn=cluster_arn)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator
    accepting what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _gone(fn) -> bool:
    """True once fn() raises ResourceNotFoundException; False while it still succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


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
