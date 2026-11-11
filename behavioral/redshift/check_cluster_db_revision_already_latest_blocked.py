"""cluster-db-revision-already-latest-blocked."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-db-revision-already-latest-blocked"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


_ON_LATEST = (
    "Modification of cluster-db-revision was skipped. The cluster is already on the requested db-revision."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision on a freshly created cluster is rejected with ClusterOnLatestRevision and
    its exact message, the revision number is untouched, and DescribeClusterDbRevisions succeeds."""
    redshift = ctx.client("redshift")
    cluster_id = _create_available_cluster(ctx, "dbrev")

    revisions = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)["ClusterDbRevisions"]
    assert revisions, "expected exactly one ClusterDbRevisions entry for a live cluster"
    current_revision = revisions[0]["CurrentDatabaseRevision"]
    before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterRevisionNumber"]

    code, message = _error(
        lambda: redshift.modify_cluster_db_revision(
            ClusterIdentifier=cluster_id, RevisionTarget=current_revision
        )
    )
    assert code == "ClusterOnLatestRevision", f"expected ClusterOnLatestRevision, got {code}"
    assert message == _ON_LATEST, f"expected {_ON_LATEST!r}, got {message!r}"

    # Effect absent: the revision number did not change.
    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterRevisionNumber"]
    assert after == before, f"ClusterRevisionNumber changed despite rejected call: {before!r} -> {after!r}"

    # Positive control: the read-only DescribeClusterDbRevisions for the same cluster still works.
    control = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)["ClusterDbRevisions"]
    assert control and control[0]["ClusterIdentifier"] == cluster_id, (
        f"expected describe_cluster_db_revisions to still report {cluster_id!r}, got {control!r}"
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _orderable_node_type(redshift, cluster_type: str = "single-node") -> str:
    """A NodeType the region offers for *cluster_type* -- queried rather than hardcoded,
    because which node types (e.g. dc2.large) accept new clusters varies by account and region."""
    # large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
    preference = ("ra3.xlplus", "ra3.large", "dc2.large", "ra3.4xlarge")
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in preference if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _create_available_cluster(ctx, tag: str) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name(f"sim2real-behav-{tag}-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_orderable_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_random_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=1200.0)
    return cluster_id


def _wait_cluster_status(
    ctx, cluster_id: str, want: str, timeout_s: float = 1200.0, interval_s: float = 15.0
) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        last = clusters[0]["ClusterStatus"] if clusters else None
        if last == want:
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {want!r} (last={last!r}) in {timeout_s}s")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
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
