"""cluster-create-nonexistent-subnet-rejected-with-positive-control."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-nonexistent-subnet-rejected-with-positive-control"
GROUP = "cluster-lifecycle"
SERVICES = ["cloudhsmv2"]

_HSM_TYPE = "hsm2m.medium"
_FAKE_SUBNET = "subnet-" + "f" * 17


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster naming a well-formed but nonexistent subnet is rejected and creates
    nothing, while the same call against a real subnet of this run's own network succeeds
    and DeleteCluster removes it.
    """
    chv2 = ctx.client("cloudhsmv2")
    network = ctx.network()
    az = network.availability_zones[0]
    subnet = network.subnets[az]

    before = _clusters_in_vpc(chv2, network.vpc_id)
    assert before == [], f"expected no cluster in this run's own VPC yet, found {before!r}"

    # ----- negative: a well-formed but nonexistent subnet is rejected -----
    code, message = _error(lambda: chv2.create_cluster(
        HsmType=_HSM_TYPE, Mode="FIPS", SubnetIds=[_FAKE_SUBNET],
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    ))
    assert code == "CloudHsmResourceNotFoundException", (
        f"expected a nonexistent subnet to be rejected not-found, got {code}: {message!r}"
    )
    assert message == f"The subnet ID '{_FAKE_SUBNET}' does not exist", (
        f"unexpected rejection message: {message!r}"
    )

    after_rejection = _clusters_in_vpc(chv2, network.vpc_id)
    assert after_rejection == [], (
        f"a rejected CreateCluster must not create anything, found {after_rejection!r}"
    )

    # ----- positive control: the same call against a real subnet succeeds -----
    cluster = chv2.create_cluster(
        HsmType=_HSM_TYPE, Mode="FIPS", SubnetIds=[subnet],
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )["Cluster"]
    cluster_id = cluster["ClusterId"]
    ctx.on_cleanup(lambda: _safety_net_delete_cluster(ctx, chv2, cluster_id))
    assert cluster_id.startswith("cluster-"), f"expected a cluster- id, got {cluster_id!r}"
    assert cluster["State"] == "CREATE_IN_PROGRESS", (
        f"expected CreateCluster to report CREATE_IN_PROGRESS synchronously, got {cluster['State']!r}"
    )

    uninitialized = _await_cluster_state(chv2, cluster_id, "UNINITIALIZED")
    assert uninitialized["Hsms"] == [], (
        f"expected no HSMs on a freshly-created cluster, got {uninitialized['Hsms']!r}"
    )
    assert uninitialized["SubnetMapping"] == {az: subnet}, (
        f"expected the single real subnet to be accepted, got {uninitialized['SubnetMapping']!r}"
    )

    deleted = chv2.delete_cluster(ClusterId=cluster_id)["Cluster"]
    assert deleted["State"] == "DELETE_IN_PROGRESS", (
        f"expected DeleteCluster to report DELETE_IN_PROGRESS synchronously, got {deleted['State']!r}"
    )
    _await_cluster_gone(chv2, cluster_id)

    final = _clusters_in_vpc(chv2, network.vpc_id)
    assert final == [], f"expected the deleted cluster to be gone from this run's VPC, found {final!r}"


def _clusters_in_vpc(chv2, vpc_id):
    """Every cluster in this run's own VPC, by id, so a sibling run's clusters never count."""
    clusters = []
    paginator = chv2.get_paginator("describe_clusters")
    for page in paginator.paginate(Filters={"vpcIds": [vpc_id]}):
        clusters.extend(c["ClusterId"] for c in page["Clusters"] if c["State"] != "DELETED")
    return clusters


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
