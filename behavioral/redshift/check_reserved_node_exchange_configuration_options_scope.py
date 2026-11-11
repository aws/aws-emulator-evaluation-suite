"""reserved-node-exchange-configuration-options-scope."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "reserved-node-exchange-configuration-options-scope"
GROUP = "data-plane"
SERVICES = ["redshift"]

ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "Aa1!" + secrets.token_urlsafe(18)
# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


# ===== helpers =====


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _cluster_status(rs, cluster_id):
    try:
        resp = rs.describe_clusters(ClusterIdentifier=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _wait_for_available(rs, cluster_id, timeout_s=660, interval_s=15):
    deadline = time.time() + timeout_s
    terminal_bad = {
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
    }
    while True:
        status = _cluster_status(rs, cluster_id)
        if status == "available":
            return
        if status in terminal_bad:
            raise AssertionError(
                f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
            )
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for cluster {cluster_id} to become "
                f"available; last status={status!r}"
            )
        time.sleep(interval_s)


def _delete_cluster(rs, cluster_id):
    """Teardown: a cluster still 'creating' may refuse deletion, so
    retry within a bounded window."""
    deadline = time.time() + 240
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] in _NOT_FOUND_CLUSTER:
                return
            if exc.response["Error"]["Code"] != "InvalidClusterState" or time.time() >= deadline:
                raise
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetReservedNodeExchangeConfigurationOptions rejects a bogus cluster id, answers a live
    non-DS2 cluster's resize path with UnsupportedOperationFault "You can only exchange DS2
    reserved nodes." and fabricates no SourceReservedNode, leaving no resize in flight."""
    redshift = ctx.client("redshift")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    bogus_cluster_id = ctx.unique_name("sim2real-behav-rs-rnscope-bogus-")
    bogus_code, bogus_message = _error(
        lambda: redshift.get_reserved_node_exchange_configuration_options(
            ActionType="resize-cluster", ClusterIdentifier=bogus_cluster_id
        )
    )
    assert bogus_code == "ClusterNotFound", (
        f"expected ClusterNotFound for a nonexistent cluster, got {bogus_code!r}"
    )
    expected_bogus = f"The cluster {bogus_cluster_id} was not found."
    assert bogus_message == expected_bogus, (
        f"expected message {expected_bogus!r}, got {bogus_message!r}"
    )

    cluster_id = ctx.unique_name("sim2real-behav-rs-rnscope-")
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    _wait_for_available(redshift, cluster_id)

    code, message = _error(
        lambda: redshift.get_reserved_node_exchange_configuration_options(
            ActionType="resize-cluster", ClusterIdentifier=cluster_id
        )
    )
    assert code == "UnsupportedOperation", f"expected UnsupportedOperation, got {code!r}: {message}"
    assert message == "You can only exchange DS2 reserved nodes.", (
        f"expected the DS2-only restriction message, got {message!r}"
    )

    resize_code, resize_message = _error(lambda: redshift.describe_resize(ClusterIdentifier=cluster_id))
    assert resize_code == "ResizeNotFound", (
        f"cluster {cluster_id} must have no resize in flight after a rejected exchange, "
        f"got {resize_code!r}"
    )
    expected_resize = f"No Resize found for Cluster {cluster_id}"
    assert resize_message == expected_resize, (
        f"expected message {expected_resize!r}, got {resize_message!r}"
    )


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.

    The 1500 s window fits this suite's 1800 s teardown budget.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
