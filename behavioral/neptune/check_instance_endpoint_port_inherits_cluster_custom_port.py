"""instance-endpoint-port-inherits-cluster-custom-port."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-endpoint-port-inherits-cluster-custom-port"
GROUP = "cluster-lifecycle"
SERVICES = ["neptune"]

_CUSTOM_PORT = 8183


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB instance created in a cluster whose Port was set away from the engine default,
    with the instance's own Port left unset, reports the cluster's port as its Endpoint.Port.
    """
    neptune = ctx.client("neptune")
    network = ctx.network()

    cluster_id = ctx.unique_name("sim2real-neptune-cp-")
    instance_id = ctx.unique_name("sim2real-neptune-cp-")
    subnet_group_name = ctx.unique_name("sim2real-neptune-cp-sng-")

    neptune.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real neptune custom cluster port check",
        SubnetIds=network.subnet_ids,
        Tags=[{"Key": "Name", "Value": subnet_group_name}],
    )
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
        "DBSubnetGroupNotFoundFault",
    ))

    created_cluster = neptune.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="neptune",
        Port=_CUSTOM_PORT,
        DBSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "Name", "Value": cluster_id}],
    )["DBCluster"]
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault",
    ))
    assert created_cluster["Port"] == _CUSTOM_PORT, created_cluster

    cluster = _await_cluster_status(neptune, cluster_id, "available")
    assert cluster["Port"] == _CUSTOM_PORT, cluster

    # ----- CreateDBInstance, with no Port of its own -----
    created_instance = neptune.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        DBInstanceClass="db.r5.large",
        Engine="neptune",
        PubliclyAccessible=False,
        Tags=[{"Key": "Name", "Value": instance_id}],
    )["DBInstance"]
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_instance(DBInstanceIdentifier=instance_id),
        "DBInstanceNotFound",
    ))
    assert created_instance["DBInstanceIdentifier"] == instance_id, created_instance
    assert created_instance["DBClusterIdentifier"] == cluster_id, created_instance

    instance = _await_instance_status(neptune, instance_id, "available")
    assert instance["Endpoint"]["Port"] == _CUSTOM_PORT, (
        f"instance endpoint port {instance['Endpoint']['Port']!r} should be the cluster's own "
        f"custom port {_CUSTOM_PORT!r}, inherited with no Port of its own"
    )

    # ----- DescribeDBInstances, a separate read, confirms the same value -----
    described = neptune.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"]
    assert len(described) == 1, described
    assert described[0]["Endpoint"]["Port"] == _CUSTOM_PORT, described[0]["Endpoint"]

    # ----- DeleteDBInstance, then DeleteDBCluster -----
    neptune.delete_db_instance(DBInstanceIdentifier=instance_id)
    _await_instance_gone(neptune, instance_id)

    neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    gone_code, gone_message = _await_cluster_gone(neptune, cluster_id)
    assert gone_code == "DBClusterNotFoundFault", gone_code
    assert gone_message == f"DBCluster {cluster_id} not found.", gone_message


# ===== helpers =====
def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _await_cluster_status(neptune, cluster_id, want_status, timeout_s=600):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == want_status:
            return desc
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id!r} never reached {want_status!r} within {timeout_s}s "
        f"(last status={desc['Status'] if desc else None!r})"
    )


def _await_instance_status(neptune, instance_id, want_status, timeout_s=900):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = neptune.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if desc["DBInstanceStatus"] == want_status:
            return desc
        time.sleep(2)
    raise AssertionError(
        f"instance {instance_id!r} never reached {want_status!r} within {timeout_s}s "
        f"(last status={desc['DBInstanceStatus'] if desc else None!r})"
    )


def _await_instance_gone(neptune, instance_id, timeout_s=900):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            neptune.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"instance {instance_id!r} never disappeared within {timeout_s}s")


def _await_cluster_gone(neptune, cluster_id, timeout_s=600) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err["Message"]
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id!r} never disappeared within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
