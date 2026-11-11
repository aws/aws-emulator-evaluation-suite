"""ordering-modify-cluster-db-revision-sequential."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ordering-modify-cluster-db-revision-sequential"
GROUP = "ordering"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision rejects a fabricated RevisionTarget with InvalidParameterValue (not
    ClusterOnLatestRevision) and the exact message, leaves the revision unchanged, and the cluster
    stays mutable."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cid = _create_available_cluster(ctx, redshift)

    revisions = _poll_for_revision_info(redshift, cid, timeout_s=300.0)
    current_revision = revisions["CurrentDatabaseRevision"]
    assert current_revision, f"cluster {cid} reported no CurrentDatabaseRevision: {revisions!r}"

    legit_targets = {t["DatabaseRevision"] for t in revisions.get("RevisionTargets", [])}
    bogus_target = ctx.unique_name("sim2real-bogus-revision-")
    assert bogus_target not in legit_targets, (
        f"test setup invalid: fabricated target {bogus_target!r} collided with a real offer"
    )

    # The cluster can report InvalidClusterState for a few seconds right after
    # ClusterStatus flips to "available" while control-plane setup finishes; that
    # is settling, not the answer, so retry through it for a bounded window and
    # take the code that survives.
    # ClusterOnLatestRevision is reserved for a well-formed revision id the cluster need not move to.
    code, message = _modify_db_revision_settled(redshift, cid, bogus_target, timeout_s=90.0)
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a fabricated RevisionTarget, got {code!r}"
    )
    assert message == (
        "The requested database revision requires an intermediate upgrade. "
        "Use DescribeClusterDbRevisions to get the next available revision target."
    ), f"unexpected InvalidParameterValue message {message!r}"

    # Effect absent: the cluster's recorded revision must not have changed.
    after = redshift.describe_cluster_db_revisions(ClusterIdentifier=cid)["ClusterDbRevisions"][
        0
    ]["CurrentDatabaseRevision"]
    assert after == current_revision, (
        f"CurrentDatabaseRevision changed despite rejected call: {current_revision!r} -> {after!r}"
    )

    # Positive control: the same cluster the rejected call targeted is still
    # fully mutable -- a genuinely applicable mutating call on it succeeds,
    # separating "this specific fabricated target is rejected" from "every
    # ModifyClusterDbRevision-adjacent call on this cluster is rejected".
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cid}"
    redshift.create_tags(
        ResourceName=cluster_arn, Tags=[{"Key": "sim2real-positive-control", "Value": "true"}]
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: redshift.delete_tags(
                ResourceName=cluster_arn, TagKeys=["sim2real-positive-control"]
            )
        )
    )
    control_tags = redshift.describe_tags(ResourceName=cluster_arn)["TaggedResources"]
    assert any(t["Tag"]["Key"] == "sim2real-positive-control" for t in control_tags), (
        f"positive control tag missing from {cluster_arn}: {control_tags!r}"
    )


def _strong_password() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    return f"S2r9{body}x"


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this region/account."""
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
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _create_available_cluster(ctx, redshift) -> str:
    cid = ctx.unique_name("sim2real-dbrev-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cid,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_strong_password(),
        PubliclyAccessible=False,
        # Encrypted at rest, as a customer would configure it.
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )

    def _cleanup() -> None:
        _wait_for_cluster_status(redshift, cid, {"available", "paused"}, timeout_s=900.0)
        redshift.delete_cluster(ClusterIdentifier=cid, SkipFinalClusterSnapshot=True)

    ctx.on_cleanup(_cleanup)
    _wait_for_cluster_status(redshift, cid, {"available"}, timeout_s=900.0)
    return cid


def _poll_for_revision_info(redshift, cid: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        revisions = redshift.describe_cluster_db_revisions(ClusterIdentifier=cid)[
            "ClusterDbRevisions"
        ]
        if revisions:
            last = revisions[0]
            if last.get("CurrentDatabaseRevision"):
                return last
        time.sleep(2)
    raise AssertionError(f"cluster {cid} never reported a CurrentDatabaseRevision: {last}")


def _wait_for_cluster_status(redshift, cid: str, ok_statuses, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = redshift.describe_clusters(ClusterIdentifier=cid)
        clusters = resp.get("Clusters", [])
        if not clusters:
            return
        status = clusters[0]["ClusterStatus"]
        if status in ok_statuses:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cid} never reached {ok_statuses} within {timeout_s}s")


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _modify_db_revision_settled(
    redshift, cid: str, revision_target: str, timeout_s: float
) -> tuple[str | None, str | None]:
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error(
            lambda: redshift.modify_cluster_db_revision(
                ClusterIdentifier=cid, RevisionTarget=revision_target
            )
        )
        if code != "InvalidClusterState":
            return code, message
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {cid} never settled out of InvalidClusterState within {timeout_s}s"
            )
        time.sleep(2)


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


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
