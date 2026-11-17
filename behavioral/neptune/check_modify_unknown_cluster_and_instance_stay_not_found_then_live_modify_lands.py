"""modify-unknown-cluster-and-instance-stay-not-found-then-live-modify-lands."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-unknown-cluster-and-instance-stay-not-found-then-live-modify-lands"
GROUP = "negative-classes"
SERVICES = ["neptune"]

_MISSING_CLUSTER_MODIFY = ("DBClusterNotFoundFault", "DBCluster not found")
_MISSING_INSTANCE_MODIFY_CLASS = "db.t3.medium"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _teardown_and_await_gone(delete, describe, not_found_code: str, budget_s=600.0, step_s=3.0):
    """Delete, then poll ``describe`` until it raises ``not_found_code`` (a dependent delete,
    like a subnet group's, can otherwise run while this resource is still ``deleting``)."""

    def run_undo() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != not_found_code:
                raise
            return
        deadline = time.monotonic() + budget_s
        while True:
            try:
                describe()
            except ClientError as exc:
                if exc.response["Error"]["Code"] == not_found_code:
                    return
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"still present {budget_s}s after its delete was accepted")
            time.sleep(step_s)

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Asserts ``fn()`` raises a ClientError with exactly ``code`` and ``message``."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For identifiers that do not exist, ModifyDBCluster answers DBClusterNotFoundFault and
    ModifyDBInstance answers DBInstanceNotFound, and Describe still answers not-found afterwards;
    a CopyTagsToSnapshot modify on a live cluster is applied and reads back as True.
    """
    neptune = ctx.client("neptune")
    network = ctx.network()

    subnet_group_name = ctx.unique_name("sim2real-neptune-modunk-sng-")
    neptune.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real neptune modify-unknown-identifier check",
        SubnetIds=network.subnet_ids,
        Tags=[{"Key": "Name", "Value": subnet_group_name}],
    )
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
        "DBSubnetGroupNotFoundFault",
    ))

    cluster_id = ctx.unique_name("sim2real-neptune-modunk-cl-")
    neptune.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="neptune",
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "Name", "Value": cluster_id}],
    )
    ctx.on_cleanup(_teardown_and_await_gone(
        lambda: neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id),
        "DBClusterNotFoundFault",
    ))
    cluster = _poll_until_cluster_status(neptune, cluster_id, "available")
    assert cluster["CopyTagsToSnapshot"] is False, cluster

    # ----- cluster: modify, then describe, an absent identifier -----
    missing_cluster_id = ctx.unique_name("sim2real-neptune-modunk-missing-cl-")
    expect_error(
        lambda: neptune.modify_db_cluster(
            DBClusterIdentifier=missing_cluster_id, CopyTagsToSnapshot=True
        ),
        *_MISSING_CLUSTER_MODIFY,
    )
    missing_cluster_describe = (
        "DBClusterNotFoundFault", f"DBCluster {missing_cluster_id} not found."
    )
    expect_error(
        lambda: neptune.describe_db_clusters(DBClusterIdentifier=missing_cluster_id),
        *missing_cluster_describe,
    )

    # ----- instance: modify, then describe, an absent identifier -----
    missing_instance_id = ctx.unique_name("sim2real-neptune-modunk-missing-in-")
    missing_instance_modify = (
        "DBInstanceNotFound", f"DB instance not found: {missing_instance_id}"
    )
    expect_error(
        lambda: neptune.modify_db_instance(
            DBInstanceIdentifier=missing_instance_id,
            DBInstanceClass=_MISSING_INSTANCE_MODIFY_CLASS,
        ),
        *missing_instance_modify,
    )
    missing_instance_describe = (
        "DBInstanceNotFound", f"DBInstance {missing_instance_id} not found."
    )
    expect_error(
        lambda: neptune.describe_db_instances(DBInstanceIdentifier=missing_instance_id),
        *missing_instance_describe,
    )

    # ----- the same CopyTagsToSnapshot modify on the live cluster is applied -----
    modified = neptune.modify_db_cluster(
        DBClusterIdentifier=cluster_id, CopyTagsToSnapshot=True, ApplyImmediately=True
    )["DBCluster"]
    assert modified["CopyTagsToSnapshot"] is True, modified

    settled = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert settled["CopyTagsToSnapshot"] is True, settled
    assert settled["DBClusterIdentifier"] == cluster_id, settled


def _poll_until_cluster_status(neptune, cluster_id, want_status, budget_s=600.0, step_s=3.0):
    """Describe ``cluster_id`` until its Status reads ``want_status``; raises past the budget."""
    deadline = time.monotonic() + budget_s
    seen = None
    while True:
        seen = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if seen["Status"] == want_status:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {cluster_id!r} still at status {seen['Status']!r} after {budget_s}s, "
                f"expected {want_status!r}"
            )
        time.sleep(step_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
