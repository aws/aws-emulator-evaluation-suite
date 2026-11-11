"""cluster-duplicate-subnet-collapses-to-one-az-then-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-duplicate-subnet-collapses-to-one-az-then-lifecycle"
GROUP = "cluster-lifecycle"
SERVICES = ["cloudhsmv2"]

_HSM_TYPE = "hsm2m.medium"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster given the same subnet twice de-duplicates to a single-AZ cluster rather
    than rejecting the request. The cluster reaches UNINITIALIZED with no HSMs, its tags and
    a BackupRetentionPolicy change both round-trip, and DeleteCluster removes it for good.
    """
    chv2 = ctx.client("cloudhsmv2")
    network = ctx.network()
    azs = network.availability_zones
    assert azs, f"need a subnet AZ, found {azs!r}"
    subnet_a = network.subnets[azs[0]]

    before = _clusters_in_vpc(chv2, network.vpc_id)
    assert before == [], f"expected no cluster in this run's own VPC yet, found {before!r}"

    # ----- the same subnet given twice is accepted and collapses to one AZ, not rejected -----
    cluster = chv2.create_cluster(
        HsmType=_HSM_TYPE, Mode="FIPS", SubnetIds=[subnet_a, subnet_a],
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )["Cluster"]
    cluster_id = cluster["ClusterId"]
    ctx.on_cleanup(lambda: _safety_net_delete_cluster(ctx, chv2, cluster_id))
    assert cluster_id.startswith("cluster-"), f"expected a cluster- id, got {cluster_id!r}"
    assert cluster["State"] == "CREATE_IN_PROGRESS", (
        f"expected CreateCluster to report CREATE_IN_PROGRESS synchronously, got {cluster['State']!r}"
    )
    assert cluster["SubnetMapping"] == {azs[0]: subnet_a}, (
        f"expected the duplicate subnet to collapse to the single AZ {azs[0]!r}, "
        f"got {cluster['SubnetMapping']!r}"
    )

    uninitialized = _await_cluster_state(chv2, cluster_id, "UNINITIALIZED")
    assert uninitialized["Hsms"] == [], (
        f"expected no HSMs on a freshly-created cluster, got {uninitialized['Hsms']!r}"
    )
    assert uninitialized["BackupPolicy"] == "DEFAULT", (
        f"expected BackupPolicy DEFAULT, got {uninitialized['BackupPolicy']!r}"
    )
    assert uninitialized.get("SecurityGroup"), (
        f"expected AWS to provision a security group for the cluster, got {uninitialized.get('SecurityGroup')!r}"
    )
    assert uninitialized.get("Certificates", {}) == {}, (
        f"expected no certificates before any HSM exists, got {uninitialized.get('Certificates')!r}"
    )

    # ----- tag round trip on the real cluster -----
    initial_tags = _tag_map(chv2, cluster_id)
    assert initial_tags.get("sim2real") == CHECK, (
        f"expected the creation tag to round-trip, got {initial_tags!r}"
    )

    chv2.tag_resource(ResourceId=cluster_id, TagList=[{"Key": "sim2real-extra", "Value": "roundtrip"}])
    added_tags = _tag_map(chv2, cluster_id)
    assert added_tags.get("sim2real-extra") == "roundtrip", (
        f"expected TagResource to round-trip through ListTags, got {added_tags!r}"
    )

    chv2.untag_resource(ResourceId=cluster_id, TagKeyList=["sim2real-extra"])
    removed_tags = _tag_map(chv2, cluster_id)
    assert "sim2real-extra" not in removed_tags, (
        f"expected UntagResource to remove the key from ListTags, got {removed_tags!r}"
    )

    # ----- ModifyCluster's BackupRetentionPolicy change needs no HSM and persists -----
    modified = chv2.modify_cluster(
        ClusterId=cluster_id, BackupRetentionPolicy={"Type": "DAYS", "Value": "200"},
    )["Cluster"]
    assert modified["BackupRetentionPolicy"] == {"Type": "DAYS", "Value": "200"}, (
        f"expected ModifyCluster to report the new retention policy, got {modified['BackupRetentionPolicy']!r}"
    )
    redescribed = _describe_cluster_or_none(chv2, cluster_id)
    assert redescribed["BackupRetentionPolicy"] == {"Type": "DAYS", "Value": "200"}, (
        f"expected the retention change to persist across a later DescribeClusters, "
        f"got {redescribed['BackupRetentionPolicy']!r}"
    )

    # ----- delete and confirm it is gone everywhere -----
    deleted = chv2.delete_cluster(ClusterId=cluster_id)["Cluster"]
    assert deleted["State"] == "DELETE_IN_PROGRESS", (
        f"expected DeleteCluster to report DELETE_IN_PROGRESS synchronously, got {deleted['State']!r}"
    )
    _await_cluster_gone(chv2, cluster_id)

    gone_code, gone_message = _error(lambda: chv2.list_tags(ResourceId=cluster_id))
    assert gone_code == "CloudHsmResourceNotFoundException", (
        f"expected ListTags on a deleted cluster to report not-found, got {gone_code}: {gone_message!r}"
    )
    assert gone_message == f"The resource '{cluster_id}' was not found.", (
        f"unexpected not-found message: {gone_message!r}"
    )


def _clusters_in_vpc(chv2, vpc_id):
    """Every cluster in this run's own VPC, by id, so a sibling run's clusters never count."""
    clusters = []
    paginator = chv2.get_paginator("describe_clusters")
    for page in paginator.paginate(Filters={"vpcIds": [vpc_id]}):
        clusters.extend(c["ClusterId"] for c in page["Clusters"])
    return clusters


def _tag_map(chv2, cluster_id):
    tags = []
    paginator = chv2.get_paginator("list_tags")
    for page in paginator.paginate(ResourceId=cluster_id):
        tags.extend(page["TagList"])
    return {t["Key"]: t["Value"] for t in tags}


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn()`` raises. An unexpected SUCCESS raises, so an
    over-permissive target accepting input real AWS rejects is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _describe_cluster_or_none(chv2, cluster_id):
    """A well-formed but nonexistent clusterId returns an empty Clusters list, not an error."""
    clusters = chv2.describe_clusters(Filters={"clusterIds": [cluster_id]})["Clusters"]
    return clusters[0] if clusters else None


def _await_cluster_state(chv2, cluster_id, want_state, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    cluster = None
    while time.monotonic() < deadline:
        cluster = _describe_cluster_or_none(chv2, cluster_id)
        if cluster and cluster["State"] == want_state:
            return cluster
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id!r} never reached {want_state!r} within {timeout_s}s "
        f"(last state={cluster['State'] if cluster else 'MISSING'!r})"
    )


def _await_cluster_gone(chv2, cluster_id, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    cluster = None
    while time.monotonic() < deadline:
        cluster = _describe_cluster_or_none(chv2, cluster_id)
        if cluster is None or cluster["State"] == "DELETED":
            return
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id!r} never disappeared within {timeout_s}s "
        f"(last state={cluster['State'] if cluster else 'MISSING'!r})"
    )


# One deadline shared by the check's one teardown, inside the suite's cleanup budget.
_TEARDOWN_S = 240.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _request_delete(fn) -> str:
    """A teardown delete: not-found means gone, the in-progress refusal is retried by the caller.
    Returns the refusal's message, or "" when the delete was accepted or the resource is gone."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "CloudHsmInvalidRequestException":
            return exc.response["Error"].get("Message", "")
        if code != "CloudHsmResourceNotFoundException":
            raise
    return ""


def _safety_net_delete_cluster(ctx, chv2, cluster_id) -> None:
    """Delete the cluster (idempotent: a prior success in ``run`` makes this a not-found no-op)
    and poll until it reads DELETED or disappears, to the shared deadline."""
    deadline = _deadline(ctx)
    refused = ""
    while True:
        cluster = _describe_cluster_or_none(chv2, cluster_id)
        if cluster is None or cluster["State"] == "DELETED":
            return
        if not cluster["State"].endswith("_IN_PROGRESS"):
            refused = _request_delete(lambda: chv2.delete_cluster(ClusterId=cluster_id)) or refused
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {cluster_id!r} still {cluster['State']!r} at the teardown deadline"
                f" (last refusal: {refused!r})"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
