"""create-control-panel-nonexistent-cluster-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-control-panel-nonexistent-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """CreateControlPanel with a ClusterArn that does not exist is refused with ValidationException
    and creates no panel by that name, while the same call on a real cluster succeeds.
    """
    client = ctx.client("route53-recovery-control-config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster_arn = (
        f"arn:aws:route53-recovery-control::{account_id}:cluster/"
        "00000000-0000-0000-0000-000000000000"
    )

    # positive control: a real cluster accepts CreateControlPanel
    cluster_arn = _create_cluster_with_retry(
        client,
        ctx.unique_name("sim2real-r53arc-cluster-"),
        resource_tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(client, cluster_arn))
    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn,
        ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-"),
        Tags={"sim2real-check": CHECK},
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _delete_control_panel_and_wait(client, panel_arn))
    described_arn = client.describe_control_panel(ControlPanelArn=panel_arn)["ControlPanel"][
        "ControlPanelArn"
    ]
    assert described_arn == panel_arn, described_arn

    rejected_name = ctx.unique_name("sim2real-r53arc-badcluster-")
    code, message = _error(
        lambda: client.create_control_panel(
            ClusterArn=bogus_cluster_arn,
            ControlPanelName=rejected_name,
        )
    )
    assert code == "ValidationException", code
    expected_message = f"Cluster {bogus_cluster_arn} does not exist."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect is absent: an independent, account-wide list has no panel with the
    # rejected name (CreateControlPanel takes no ClusterArn other than the bogus
    # one, so there is no valid cluster to scope the list to)
    all_names = [p["Name"] for p in client.list_control_panels().get("ControlPanels", [])]
    assert rejected_name not in all_names, all_names


def _create_cluster_with_retry(client, name, timeout_s=900.0, interval_s=15.0, resource_tags=None):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window —
    the account's 2-cluster quota may still be draining an async delete from a
    prior check's teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kwargs = {"ClusterName": name}
            if resource_tags:
                kwargs["Tags"] = resource_tags
            return client.create_cluster(**kwargs)["Cluster"]["ClusterArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_control_panel_and_wait(client, panel_arn, timeout_s=300.0, interval_s=5.0) -> None:
    """Teardown DeleteControlPanel: retry while the panel is still PENDING (ConflictException),
    then wait until it is gone, so the cluster delete that follows is not refused for a
    non-default control panel."""
    _delete_and_wait(
        lambda: client.delete_control_panel(ControlPanelArn=panel_arn),
        lambda: client.describe_control_panel(ControlPanelArn=panel_arn),
        f"control panel {panel_arn}",
        timeout_s,
        interval_s,
    )


def _delete_cluster_and_wait(client, cluster_arn, timeout_s=300.0, interval_s=5.0) -> None:
    """Teardown DeleteCluster: retry while the panel delete (LIFO-ordered before this one)
    still propagates, then wait until the cluster is gone, so it never strands the
    account's 2-cluster quota."""
    _delete_and_wait(
        lambda: client.delete_cluster(ClusterArn=cluster_arn),
        lambda: client.describe_cluster(ClusterArn=cluster_arn),
        f"cluster {cluster_arn}",
        timeout_s,
        interval_s,
    )


def _delete_and_wait(delete, describe, label, timeout_s, interval_s) -> None:
    """Retry delete() until AWS accepts it, then poll describe() until ResourceNotFound.
    Raises on timeout so a stranded resource surfaces as a cleanup failure."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            delete()
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            last = err.response["Error"]["Code"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"delete of {label} not accepted within {timeout_s}s (last: {last})")
        time.sleep(interval_s)
    while True:
        try:
            describe()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{label} still present {timeout_s}s after its delete")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
