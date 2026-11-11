"""cluster-db-revision-modify-transition."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "cluster-db-revision-modify-transition"
GROUP = "state-machine"
SERVICES = ["redshift"]


_ON_LATEST = (
    "Modification of cluster-db-revision was skipped. The cluster is already on the requested db-revision."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision to a fresh cluster's current revision is ClusterOnLatestRevision.

    Both revision fields stay unchanged, and tagging the same cluster still succeeds."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cluster_id = _create_available_cluster(ctx)

    revisions = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)[
        "ClusterDbRevisions"
    ]
    assert len(revisions) == 1, f"expected exactly one ClusterDbRevisions entry, got {len(revisions)}"
    current_revision = revisions[0]["CurrentDatabaseRevision"]
    assert current_revision, "CurrentDatabaseRevision was empty for a live cluster"

    before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    revision_number_before = before["ClusterRevisionNumber"]

    code, message = _error(
        lambda: redshift.modify_cluster_db_revision(
            ClusterIdentifier=cluster_id, RevisionTarget=current_revision
        )
    )
    assert code == "ClusterOnLatestRevision", f"expected ClusterOnLatestRevision, got {code!r}"
    assert message == _ON_LATEST, f"expected {_ON_LATEST!r}, got {message!r}"

    # Effect absent: the cluster's revision and the reported db-revision are unchanged.
    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    assert after["ClusterRevisionNumber"] == revision_number_before, (
        f"ClusterRevisionNumber changed despite a rejected call: "
        f"{revision_number_before!r} -> {after['ClusterRevisionNumber']!r}"
    )

    revisions_after = redshift.describe_cluster_db_revisions(
        ClusterIdentifier=cluster_id
    )["ClusterDbRevisions"]
    assert revisions_after[0]["CurrentDatabaseRevision"] == current_revision, (
        f"CurrentDatabaseRevision changed despite a rejected call: "
        f"{current_revision!r} -> {revisions_after[0]['CurrentDatabaseRevision']!r}"
    )

    # Positive control: the rejection is specific to self-targeting, not to the cluster.
    cluster_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    redshift.create_tags(
        ResourceName=cluster_arn,
        Tags=[{"Key": "sim2real-positive-control", "Value": "true"}],
    )
    tagged = redshift.describe_tags(ResourceName=cluster_arn)["TaggedResources"]
    assert any(t["Tag"]["Key"] == "sim2real-positive-control" for t in tagged), (
        "positive control create_tags call did not take effect on the same cluster"
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _rand_password() -> str:
    return f"S2r{secrets.token_hex(4)}Aa1Xy"


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to build a Redshift cluster subnet "
            "group from; a non-shared network VPC + subnets would need to be provisioned first"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for subnet in subnets:
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    if not by_az:
        raise AssertionError("shared network has no subnets available")
    return list(by_az.values())


def _orderable_node_type(redshift, cluster_type="single-node") -> str:
    """A NodeType the region offers for *cluster_type* -- queried rather than hardcoded,
    because which node types (e.g. dc2.large) accept new clusters varies by account and region."""
    # large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
    preference = ("ra3.xlplus", "ra3.large", "dc2.large", "ra3.4xlarge")
    available = []
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


def _create_available_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    node_type = _orderable_node_type(redshift)
    subnet_ids = _default_vpc_subnets(ctx)
    subnet_group_name = ctx.unique_name("sim2real-subg-")
    redshift.create_cluster_subnet_group(
        ClusterSubnetGroupName=subnet_group_name,
        Description="sim2real behavioral fidelity check",
        SubnetIds=subnet_ids[:2] if len(subnet_ids) > 1 else subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(redshift, subnet_group_name))

    cluster_id = ctx.unique_name("sim2real-clu-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=node_type,
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        ClusterSubnetGroupName=subnet_group_name,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    waiter = redshift.get_waiter("cluster_available")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 900},
        )
    except WaiterError as exc:
        raise AssertionError(f"cluster {cluster_id} never became available: {exc}")
    return cluster_id


def _delete_cluster(redshift, cluster_id: str) -> None:
    try:
        redshift.delete_cluster(
            ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ClusterNotFound":
            return
        raise
    waiter = redshift.get_waiter("cluster_deleted")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 900},
        )
    except WaiterError:
        pass


def _safe_delete_subnet_group(redshift, name: str) -> None:
    import time

    for _ in range(20):
        try:
            redshift.delete_cluster_subnet_group(ClusterSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterSubnetGroupNotFoundFault":
                return
            if code == "InvalidClusterSubnetGroupStateFault":
                time.sleep(15)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
