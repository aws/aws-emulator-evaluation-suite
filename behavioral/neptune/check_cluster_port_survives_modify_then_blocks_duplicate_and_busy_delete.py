"""cluster-port-survives-modify-then-blocks-duplicate-and-busy-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-port-survives-modify-then-blocks-duplicate-and-busy-delete"
GROUP = "cluster-lifecycle"
SERVICES = ["neptune"]

_PORT = 8191


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _delete_cluster_and_wait(neptune, cluster_id: str, *, timeout_s: float) -> None:
    try:
        neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
        return
    _wait_cluster_gone(neptune, cluster_id, timeout_s=timeout_s)


def _delete_instance_and_wait(neptune, instance_id: str, *, timeout_s: float) -> None:
    try:
        neptune.delete_db_instance(DBInstanceIdentifier=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_instance_gone(neptune, instance_id, timeout_s=timeout_s)


def _delete_subnet_group_when_released(neptune, name: str, *, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            neptune.delete_db_subnet_group(DBSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBSubnetGroupNotFoundFault":
                return
            if code != "InvalidDBSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_cluster_status(neptune, cluster_id: str, status: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        cluster = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if cluster["Status"] == status:
            return cluster
        if time.monotonic() > deadline:
            raise AssertionError(
                f"cluster {cluster_id} never reached status {status!r}; last status {cluster['Status']!r}"
            )
        time.sleep(5)


def _wait_instance_status(neptune, instance_id: str, status: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        instance = neptune.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if instance["DBInstanceStatus"] == status:
            return instance
        if time.monotonic() > deadline:
            raise AssertionError(
                f"instance {instance_id} never reached status {status!r}; "
                f"last status {instance['DBInstanceStatus']!r}"
            )
        time.sleep(5)


def _wait_cluster_gone(neptune, cluster_id: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"cluster {cluster_id} still describable after {timeout_s}s")
        time.sleep(5)


def _wait_instance_gone(neptune, instance_id: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            neptune.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"instance {instance_id} still describable after {timeout_s}s")
        time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster's non-default Port survives unrelated ModifyDBCluster/ModifyDBInstance calls
    and matches the instance's Endpoint.Port. A duplicate create, a delete while the instance
    lives, and a describe once both are gone are each refused with an exact code and message."""
    neptune = ctx.client("neptune")
    cluster_id = ctx.unique_name("sim2real-behav-npt-clu-")
    instance_id = ctx.unique_name("sim2real-behav-npt-ins-")
    subnet_group = ctx.unique_name("sim2real-behav-npt-sng-")

    neptune.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="custom port cluster lifecycle",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_subnet_group_when_released(neptune, subnet_group, timeout_s=900))

    neptune.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="neptune",
        Port=_PORT,
        DBSubnetGroupName=subnet_group,
        DeletionProtection=False,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(neptune, cluster_id, timeout_s=900))
    created = _wait_cluster_status(neptune, cluster_id, "available", timeout_s=900)
    assert created["Port"] == _PORT, f"cluster Port was {created['Port']!r}, expected {_PORT}"

    neptune.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.medium",
        Engine="neptune",
        DBClusterIdentifier=cluster_id,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(neptune, instance_id, timeout_s=900))
    instance = _wait_instance_status(neptune, instance_id, "available", timeout_s=900)
    assert instance["Endpoint"]["Port"] == _PORT, (
        f"instance Endpoint.Port was {instance['Endpoint']['Port']!r}, expected {_PORT}"
    )

    # An unrelated ModifyDBCluster call must not disturb the cluster's Port.
    window = "sun:05:00-sun:05:30"
    neptune.modify_db_cluster(
        DBClusterIdentifier=cluster_id, PreferredMaintenanceWindow=window, ApplyImmediately=True,
    )
    modified_cluster = _wait_cluster_status(neptune, cluster_id, "available", timeout_s=600)
    assert modified_cluster["PreferredMaintenanceWindow"] == window, (
        f"PreferredMaintenanceWindow was {modified_cluster['PreferredMaintenanceWindow']!r}, expected {window!r}"
    )
    assert modified_cluster["Port"] == _PORT, (
        f"cluster Port became {modified_cluster['Port']!r} after an unrelated modify, expected {_PORT}"
    )

    # An unrelated ModifyDBInstance call must not disturb the instance's Endpoint.Port.
    instance_window = "mon:05:00-mon:05:30"
    neptune.modify_db_instance(
        DBInstanceIdentifier=instance_id,
        PreferredMaintenanceWindow=instance_window,
        ApplyImmediately=True,
    )
    modified_instance = _wait_instance_status(neptune, instance_id, "available", timeout_s=600)
    assert modified_instance["PreferredMaintenanceWindow"] == instance_window, (
        f"PreferredMaintenanceWindow was {modified_instance['PreferredMaintenanceWindow']!r}, "
        f"expected {instance_window!r}"
    )
    assert modified_instance["Endpoint"]["Port"] == _PORT, (
        f"instance Endpoint.Port became {modified_instance['Endpoint']['Port']!r} "
        f"after an unrelated modify, expected {_PORT}"
    )

    # A duplicate create is refused; the original cluster's Port is unaffected (positive control).
    _ALREADY_EXISTS = ("DBClusterAlreadyExistsFault", "DB Cluster already exists")
    _expect_error(
        lambda: neptune.create_db_cluster(
            DBClusterIdentifier=cluster_id, Engine="neptune", DBSubnetGroupName=subnet_group,
        ),
        *_ALREADY_EXISTS,
    )
    after_duplicate = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert after_duplicate["Port"] == _PORT, (
        f"cluster Port changed to {after_duplicate['Port']!r} after a refused duplicate create"
    )

    # A delete while the instance lives is refused; the cluster stays available (positive control).
    _NOT_EMPTY = (
        "InvalidDBClusterStateFault",
        "Cluster can't be deleted. It still contains DB instances in a non-deleting state.",
    )
    _expect_error(
        lambda: neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        *_NOT_EMPTY,
    )
    after_busy_delete = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert after_busy_delete["Status"] == "available", (
        f"cluster left status {after_busy_delete['Status']!r} after a refused delete"
    )

    # Delete the instance, then the cluster, for real.
    neptune.delete_db_instance(DBInstanceIdentifier=instance_id)
    _wait_instance_gone(neptune, instance_id, timeout_s=900)
    neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    _wait_cluster_gone(neptune, cluster_id, timeout_s=900)

    _INSTANCE_GONE = ("DBInstanceNotFound", f"DBInstance {instance_id} not found.")
    _expect_error(lambda: neptune.describe_db_instances(DBInstanceIdentifier=instance_id), *_INSTANCE_GONE)
    _CLUSTER_GONE = ("DBClusterNotFoundFault", f"DBCluster {cluster_id} not found.")
    _expect_error(lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id), *_CLUSTER_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
