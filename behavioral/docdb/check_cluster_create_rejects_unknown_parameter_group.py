"""cluster-create-rejects-unknown-parameter-group."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-rejects-unknown-parameter-group"
GROUP = "rejected"
SERVICES = ["docdb"]


def _admin_password() -> str:
    """A fresh password meeting DocDB's constraints (8-100 printable ASCII, no / " @)."""
    alphabet = string.ascii_letters + string.digits
    return "Sim2Real" + "".join(secrets.choice(alphabet) for _ in range(12))


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _await_cluster_status(docdb, cluster_id, want_status, timeout_s=600):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = docdb.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == want_status:
            return desc
        time.sleep(5)
    raise AssertionError(
        f"cluster {cluster_id!r} never reached {want_status!r} within {timeout_s}s "
        f"(last status={desc['Status'] if desc else None!r})"
    )


def _delete_cluster_and_wait(docdb, cluster_id, timeout_s=600, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            docdb.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            docdb.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id!r} never disappeared within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBCluster rejects a DBClusterParameterGroupName that does not exist, with the
    exact DBClusterParameterGroupNotFound fault, and the same subnet group accepts a cluster
    that names no explicit cluster parameter group.
    """
    docdb = ctx.client("docdb")
    net = ctx.network()

    subgrp_name = ctx.unique_name("sim2real-behav-docdb-sg-")
    docdb.create_db_subnet_group(
        DBSubnetGroupName=subgrp_name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=net.subnet_ids[:2],
    )
    ctx.on_cleanup(lambda: docdb.delete_db_subnet_group(DBSubnetGroupName=subgrp_name))

    admin_password = _admin_password()
    bogus_param_group = ctx.unique_name("sim2real-behav-docdb-missing-pg-")
    rejected_cluster_id = ctx.unique_name("sim2real-behav-docdb-rejected-")
    code, message = _error(
        lambda: docdb.create_db_cluster(
            DBClusterIdentifier=rejected_cluster_id,
            Engine="docdb",
            MasterUsername="dbadmin",
            MasterUserPassword=admin_password,
            DBSubnetGroupName=subgrp_name,
            DBClusterParameterGroupName=bogus_param_group,
        )
    )
    assert code == "DBClusterParameterGroupNotFound", (
        f"expected DBClusterParameterGroupNotFound, got {code!r}"
    )
    expected_message = f"DBClusterParameterGroup not found: {bogus_param_group}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    gone = _error(lambda: docdb.describe_db_clusters(DBClusterIdentifier=rejected_cluster_id))
    expected_gone = ("DBClusterNotFoundFault", f"DBCluster {rejected_cluster_id} not found.")
    assert gone == expected_gone, (
        f"rejected create_db_cluster must not leave a cluster named {rejected_cluster_id!r} "
        f"behind: expected {expected_gone!r} from the filtered describe, got {gone!r}"
    )

    # positive control: the same subnet group, with no explicit cluster parameter group, succeeds
    # and settles on the engine's own default.
    cluster_id = ctx.unique_name("sim2real-behav-docdb-ok-")
    created = docdb.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="docdb",
        MasterUsername="dbadmin",
        MasterUserPassword=admin_password,
        DBSubnetGroupName=subgrp_name,
        BackupRetentionPeriod=1,
        StorageEncrypted=False,
        DeletionProtection=False,
    )["DBCluster"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(docdb, cluster_id))
    assert created["DBClusterIdentifier"] == cluster_id, created
    assert created["DBClusterParameterGroup"].startswith("default."), created
    # positive control for the absence read: the same filtered describe finds an existing cluster.
    described = docdb.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"]
    assert [c["DBClusterIdentifier"] for c in described] == [cluster_id], described

    settled = _await_cluster_status(docdb, cluster_id, "available")
    assert settled["DBSubnetGroup"] == subgrp_name, settled
    assert settled["DBClusterParameterGroup"] == created["DBClusterParameterGroup"], settled


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
