"""cluster-db-revision-already-latest-fault."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-db-revision-already-latest-fault"
GROUP = "error-semantics"
SERVICES = ["redshift"]


_ON_LATEST = (
    "Modification of cluster-db-revision was skipped. The cluster is already on the requested db-revision."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision with the cluster's own current revision is rejected with
    ClusterOnLatestRevision and its exact message, both revision fields are unchanged, and tagging
    the same cluster still succeeds."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cluster_id = ctx.unique_name("sim2real-dbrev-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        MasterUsername="sim2readmin",
        MasterUserPassword=_cluster_password(),
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    )

    _wait_for_cluster_status(ctx, cluster_id, "available", timeout_s=900.0)

    revisions = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)["ClusterDbRevisions"]
    assert revisions, f"expected a ClusterDbRevisions entry for {cluster_id}, got none"
    current_revision = revisions[0]["CurrentDatabaseRevision"]
    assert current_revision, f"cluster {cluster_id} reported no CurrentDatabaseRevision: {revisions[0]}"
    revision_number_before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterRevisionNumber"
    ]

    code, message = _error(
        lambda: redshift.modify_cluster_db_revision(ClusterIdentifier=cluster_id, RevisionTarget=current_revision)
    )
    assert code == "ClusterOnLatestRevision", f"expected ClusterOnLatestRevision, got {code!r}"
    assert message == _ON_LATEST, f"expected {_ON_LATEST!r}, got {message!r}"

    # Effect absent: the rejected call must not have moved the cluster's revision.
    revision_number_after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterRevisionNumber"
    ]
    assert revision_number_after == revision_number_before, (
        f"ClusterRevisionNumber changed despite rejected ModifyClusterDbRevision: "
        f"{revision_number_before!r} -> {revision_number_after!r}"
    )
    current_revision_after = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)[
        "ClusterDbRevisions"
    ][0]["CurrentDatabaseRevision"]
    assert current_revision_after == current_revision, (
        f"CurrentDatabaseRevision changed despite rejected call: {current_revision!r} -> {current_revision_after!r}"
    )

    # Positive control: the cluster remains fully mutable -- a genuinely applicable
    # mutating call on the same cluster still succeeds.
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    redshift.create_tags(ResourceName=cluster_arn, Tags=[{"Key": "sim2real-control", "Value": "true"}])
    tagged = redshift.describe_tags(ResourceName=cluster_arn)["TaggedResources"]
    assert any(t["Tag"]["Key"] == "sim2real-control" for t in tagged), (
        f"expected sim2real-control tag on {cluster_arn} after create_tags, got {tagged}"
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _cluster_password() -> str:
    return "Sim2Real" + uuid.uuid4().hex[:12] + "9!"


def _wait_for_cluster_status(ctx, cluster_id: str, target_status: str, timeout_s: float, interval_s: float = 15.0):
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = redshift.describe_clusters(ClusterIdentifier=cluster_id)
        cluster = resp["Clusters"][0]
        last = cluster.get("ClusterStatus")
        if last == target_status:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach status {target_status!r} within {timeout_s}s (last={last!r})")


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
