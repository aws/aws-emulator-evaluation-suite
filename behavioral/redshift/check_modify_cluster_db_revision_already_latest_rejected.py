"""modify-cluster-db-revision-already-latest-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-db-revision-already-latest-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision targeting the revision the cluster is already on is
    rejected with ClusterOnLatestRevision and its exact message, not accepted as a
    no-op success, and the cluster's revision number is unchanged."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # One deadline for every teardown of the run, started by the first one that runs.
    teardown_deadline: dict = {}
    cluster_id = _create_available_cluster(ctx, teardown_deadline)

    revisions = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)[
        "ClusterDbRevisions"
    ][0]
    current_revision = revisions["CurrentDatabaseRevision"]
    before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterRevisionNumber"
    ]

    code, message = _modify_db_revision_error_code(
        redshift, cluster_id, current_revision, settle_timeout_s=180.0
    )
    assert code == "ClusterOnLatestRevision", (
        f"expected ClusterOnLatestRevision, got {code!r}"
    )
    assert message == (
        "Modification of cluster-db-revision was skipped. The cluster is already on the requested db-revision."
    ), message

    # Effect absent: the rejected call must not have changed the cluster's revision.
    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterRevisionNumber"
    ]
    assert after == before, (
        f"ClusterRevisionNumber changed despite rejected call: {before!r} -> {after!r}"
    )

    # Positive control: the same, still-available cluster remains fully mutable --
    # a genuinely applicable mutating call on it still succeeds.
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    redshift.create_tags(
        ResourceName=cluster_arn, Tags=[{"Key": "sim2real-check", "Value": "true"}]
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: redshift.delete_tags(ResourceName=cluster_arn, TagKeys=["sim2real-check"])
        )
    )
    tags = redshift.describe_tags(ResourceName=cluster_arn)["TaggedResources"]
    assert any(t["Tag"]["Key"] == "sim2real-check" for t in tags), (
        f"expected sim2real-check tag on {cluster_arn}, got {tags!r}"
    )


# ===== helpers =====
def _modify_db_revision_error_code(redshift, cluster_id, revision_target, settle_timeout_s):
    """Return the (code, message) ModifyClusterDbRevision is rejected with, retrying the
    InvalidClusterState a just-available cluster can answer during a short settling window.
    """
    deadline = time.monotonic() + settle_timeout_s
    last_transient = None
    while time.monotonic() < deadline:
        try:
            result = redshift.modify_cluster_db_revision(
                ClusterIdentifier=cluster_id, RevisionTarget=revision_target
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidClusterState":
                last_transient = code
                time.sleep(2)
                continue
            return code, err.response["Error"]["Message"]
        raise AssertionError(
            f"AWS rejects this call, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError(
        f"cluster {cluster_id} still {last_transient!r} after {settle_timeout_s}s settling window"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _create_available_cluster(ctx, teardown_deadline) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-dbrev-cl-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift, teardown_deadline)
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id, teardown_deadline))
    # Redshift creates AWSServiceRoleForRedshift on an account's first cluster; until that role
    # propagates, CreateCluster answers "Unable to assume the SLR on the customer account".
    left = ctx.time_left()
    deadline = time.monotonic() + (600.0 if left is None else min(600.0, left))
    while True:
        try:
            redshift.create_cluster(
                ClusterIdentifier=cluster_id,
                NodeType="ra3.large",
                MasterUsername="sim2realadmin",
                ManageMasterPassword=True,
                ClusterType="single-node",
                PubliclyAccessible=False,
                ClusterSubnetGroupName=subnet_group,
            )
            break
        except ClientError as err:
            if "Unable to assume the SLR" not in err.response["Error"].get("Message", "") \
                    or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    return cluster_id


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _deadline(teardown_deadline: dict) -> float:
    """The run's teardown deadline, started by the first teardown that asks for it."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _delete_cluster(redshift, cluster_id: str, teardown_deadline) -> None:
    """Teardown: DeleteCluster, retrying InvalidClusterState (creating, modifying or deleting) every
    2 s, then poll every 2 s until ClusterNotFound, since the delete is asynchronous."""
    deadline = _deadline(teardown_deadline)
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"cluster {cluster_id} still listed at the teardown deadline")
        time.sleep(2)


def _network_redshift_subnet_group(ctx, client, teardown_deadline) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    ctx.on_cleanup(lambda: _delete_subnet_group(client, name, teardown_deadline))
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    return name


def _delete_subnet_group(client, name, teardown_deadline):
    """Teardown: DeleteClusterSubnetGroup, retrying InvalidClusterSubnetGroupStateFault (still in use)
    every 2 s; an absent group is done. The delete is synchronous."""
    deadline = _deadline(teardown_deadline)
    while True:
        try:
            client.delete_cluster_subnet_group(ClusterSubnetGroupName=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterSubnetGroupNotFoundFault":
                return
            if code != "InvalidClusterSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
