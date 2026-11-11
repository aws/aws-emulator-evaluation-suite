"""modify-cluster-db-revision-latest-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-db-revision-latest-blocked"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision targeting a fresh cluster's own current revision is rejected with
    ClusterOnLatestRevision and its exact message rather than accepted as a no-op, and the current
    revision does not change."""
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-dbrev-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.large",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealTest1234!",
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=900)

    # positive control: the describe call itself succeeds and returns a real current revision.
    revisions = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)[
        "ClusterDbRevisions"
    ]
    assert len(revisions) == 1, f"expected exactly one ClusterDbRevisions entry, got {revisions!r}"
    current_revision = revisions[0]["CurrentDatabaseRevision"]
    assert current_revision, f"expected a non-empty CurrentDatabaseRevision, got {current_revision!r}"

    code, message = _error(
        lambda: redshift.modify_cluster_db_revision(
            ClusterIdentifier=cluster_id, RevisionTarget=current_revision
        )
    )
    assert code == "ClusterOnLatestRevision", f"expected ClusterOnLatestRevision, got {code!r}"
    assert message == (
        "Modification of cluster-db-revision was skipped. "
        "The cluster is already on the requested db-revision."
    ), f"unexpected ClusterOnLatestRevision message {message!r}"

    # effect absent: the recorded current revision is unchanged.
    after = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)[
        "ClusterDbRevisions"
    ][0]
    assert after["CurrentDatabaseRevision"] == current_revision, (
        f"CurrentDatabaseRevision changed despite rejected call: "
        f"{current_revision!r} -> {after['CurrentDatabaseRevision']!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_status(ctx, redshift, cluster_id, target_status, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if last["ClusterStatus"] == target_status:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_status!r} (last seen: {last})")


def _delete_cluster(redshift, cluster_id):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code == "InvalidClusterState":
                time.sleep(15)
                continue
            raise
    raise AssertionError(f"could not delete cluster {cluster_id} within retry budget")


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
