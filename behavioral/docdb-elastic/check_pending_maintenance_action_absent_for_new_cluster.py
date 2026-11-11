"""pending-maintenance-action-absent-for-new-cluster."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pending-maintenance-action-absent-for-new-cluster"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a new ACTIVE cluster, GetPendingMaintenanceAction succeeds with no pendingMaintenanceActionDetails
    (absence is not ResourceNotFoundException), and ListPendingMaintenanceActions answers without that cluster."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-maint-")

    cluster_arn = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(client, cluster_arn))
    _wait_for_cluster_status(client, cluster_arn, {"ACTIVE"})

    action = client.get_pending_maintenance_action(resourceArn=cluster_arn)[
        "resourcePendingMaintenanceAction"
    ]
    reported_arn = action.get("resourceArn")
    assert reported_arn in (None, cluster_arn), (
        f"resourcePendingMaintenanceAction named a different resource: {reported_arn!r}"
    )
    assert not action.get("pendingMaintenanceActionDetails"), (
        "freshly-created cluster unexpectedly has pending maintenance action details: "
        f"{action.get('pendingMaintenanceActionDetails')!r}"
    )

    all_pending = client.list_pending_maintenance_actions(maxResults=100)
    assert "resourcePendingMaintenanceActions" in all_pending, (
        "list_pending_maintenance_actions did not return the expected key on a live "
        f"cluster (positive control), got keys={sorted(all_pending)}"
    )
    arns = [p["resourceArn"] for p in all_pending["resourcePendingMaintenanceActions"]]
    assert cluster_arn not in arns, "freshly-created cluster unexpectedly has a pending action"


def _wait_for_cluster_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


def _best_effort_delete_cluster(client, cluster_arn):
    try:
        client.delete_cluster(clusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
