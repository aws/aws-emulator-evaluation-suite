"""reboot-is-gated-by-cluster-state-across-a-pause-resume-cycle."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reboot-is-gated-by-cluster-state-across-a-pause-resume-cycle"
GROUP = "cluster-lifecycle"
SERVICES = ["redshift"]

_SINGLE_NODE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
_GONE = ("ClusterNotFound", "ClusterNotFoundFault")


def _error_code(fn) -> str:
    """The Error.Code ``fn`` raises; an unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_until_gone(delete, busy_code: str, gone_codes, deadline: float) -> None:
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code != busy_code or time.time() >= deadline:
                raise
        time.sleep(3)


_SETTLING_MESSAGE = (
    "The Cluster is being modified by a concurrent operation. "
    "Please check the Cluster's status and try again."
)


def _reboot_once_settled(rs, cluster_id: str, deadline: float) -> None:
    """RebootCluster on a freshly available cluster: an internal finishing touch can still
    report InvalidClusterState with this exact message for a short window; everything else
    raises."""
    while True:
        try:
            rs.reboot_cluster(ClusterIdentifier=cluster_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] != "InvalidClusterState" or error["Message"] != _SETTLING_MESSAGE:
                raise
            if time.time() >= deadline:
                raise
        time.sleep(2)


def _pick_single_node_type(rs) -> str:
    offered = set()
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        page = rs.describe_orderable_cluster_options(**kwargs)
        for opt in page.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") == "single-node":
                offered.add(opt["NodeType"])
        marker = page.get("Marker")
        if not marker:
            break
    for candidate in _SINGLE_NODE_PREFERENCE:
        if candidate in offered:
            return candidate
    assert offered, "this region orders no single-node cluster type"
    return sorted(offered)[0]


def _wait_for_status(rs, cluster_id: str, terminal: set[str], deadline: float) -> str:
    """Poll to a terminal cluster status; the call never reads a transitional one."""
    while True:
        status = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
        if status in terminal:
            return status
        if time.time() >= deadline:
            raise AssertionError(f"cluster {cluster_id} still {status!r} after the wait budget")
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebootCluster is refused with InvalidClusterState while the cluster is paused, and the
    identical call succeeds again once ResumeCluster returns it to 'available'.

    Reference: https://docs.aws.amazon.com/redshift/latest/APIReference/API_RebootCluster.html
    """
    rs = ctx.client("redshift")
    network = ctx.network()

    subnet_group = ctx.unique_name("sim2real-behav-rs-reboot-sn-")
    rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=subnet_group, Description=subnet_group,
        SubnetIds=network.subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=subnet_group),
        "InvalidClusterSubnetGroupStateFault", ("ClusterSubnetGroupNotFoundFault",),
        time.time() + 600,
    ))

    cluster_id = ctx.unique_name("sim2real-behav-rs-reboot-")
    rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_pick_single_node_type(rs),
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2real" + secrets.token_hex(10),
        ClusterType="single-node",
        DBName="sim2realdb",
        PubliclyAccessible=False,
        VpcSecurityGroupIds=[network.security_group_id],
        ClusterSubnetGroupName=subnet_group,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": cluster_id}],
    )
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True),
        "InvalidClusterState", _GONE, time.time() + 600,
    ))

    status = _wait_for_status(rs, cluster_id, {"available"}, time.time() + 900)
    assert status == "available", f"cluster reached {status!r}, expected 'available'"

    # Positive control: RebootCluster succeeds on an available cluster.
    _reboot_once_settled(rs, cluster_id, time.time() + 180)
    status = _wait_for_status(rs, cluster_id, {"available"}, time.time() + 600)
    assert status == "available", f"cluster reached {status!r} after a reboot, expected 'available'"

    # PauseCluster requires a recent backup; a cluster this young has no automated one yet.
    snapshot_id = ctx.unique_name("sim2real-behav-rs-reboot-snap-")
    rs.create_cluster_snapshot(SnapshotIdentifier=snapshot_id, ClusterIdentifier=cluster_id)
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: rs.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id),
        "InvalidClusterSnapshotState", ("ClusterSnapshotNotFound",), time.time() + 600,
    ))
    snap_deadline = time.time() + 600
    while True:
        snap_status = rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]["Status"]
        if snap_status == "available":
            break
        if time.time() >= snap_deadline:
            raise AssertionError(f"snapshot {snapshot_id} still {snap_status!r} after the wait budget")
        time.sleep(2)

    # PauseCluster also needs ClusterAvailabilityStatus back to "Available" after the snapshot.
    avail_deadline = time.time() + 300
    while True:
        described = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if described["ClusterAvailabilityStatus"] == "Available":
            break
        if time.time() >= avail_deadline:
            raise AssertionError(
                f"cluster availability status still {described['ClusterAvailabilityStatus']!r} "
                "after the wait budget"
            )
        time.sleep(2)

    rs.pause_cluster(ClusterIdentifier=cluster_id)
    status = _wait_for_status(rs, cluster_id, {"paused"}, time.time() + 600)
    assert status == "paused", f"cluster reached {status!r} after PauseCluster, expected 'paused'"

    code, message = None, None
    try:
        rs.reboot_cluster(ClusterIdentifier=cluster_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
    assert code == "InvalidClusterState", (
        f"RebootCluster on a paused cluster returned {code!r}, expected 'InvalidClusterState'"
    )
    expected_message = f"Cluster {cluster_id} is not in available state to reboot."
    assert message == expected_message, (
        f"RebootCluster on a paused cluster said {message!r}, expected {expected_message!r}"
    )

    # The cluster is still paused: the refused call changed nothing.
    status = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
    assert status == "paused", f"a refused RebootCluster left the cluster {status!r}, not 'paused'"

    rs.resume_cluster(ClusterIdentifier=cluster_id)
    status = _wait_for_status(rs, cluster_id, {"available"}, time.time() + 900)
    assert status == "available", f"cluster reached {status!r} after ResumeCluster, expected 'available'"

    # Beat 6: the identical call that was refused now succeeds, with the state restored.
    _reboot_once_settled(rs, cluster_id, time.time() + 180)
    status = _wait_for_status(rs, cluster_id, {"available"}, time.time() + 600)
    assert status == "available", (
        f"cluster reached {status!r} after rebooting post-resume, expected 'available'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
