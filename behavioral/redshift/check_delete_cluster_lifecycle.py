"""delete-cluster-lifecycle."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, HTTP status, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_until(probe, done, timeout_s=600, interval_s=15, what="condition"):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
PARAM_FAMILY = "redshift-1.0"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


#: A fixed single-node type rather than a DescribeOrderableClusterOptions lookup: the node-type
#: catalog is not this check's claim.
NODE_TYPE = "ra3.large"


def _cluster_params(rs, cluster_id, **overrides):
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=NODE_TYPE,
        MasterUsername=MASTER_USERNAME,
        MasterUserPassword=MASTER_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        # The request asks for an encrypted cluster.
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    params.update(overrides)
    return params


def _describe_cluster(rs, cluster_id):
    resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _cluster_status(rs, cluster_id):
    try:
        cluster = _describe_cluster(rs, cluster_id)
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    return cluster["ClusterStatus"] if cluster else None


def _wait_for_cluster_status(rs, cluster_id, target_statuses, timeout_s=600, interval_s=15):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in targets)}",
    )


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_for_cluster_status(rs, cluster_id, terminal, timeout_s=timeout_s)
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_for_cluster_gone(rs, cluster_id, timeout_s=420, interval_s=15):
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} to disappear",
    )


def _delete_cluster(rs, cluster_id):
    """Teardown: a cluster still 'creating' may refuse deletion, so
    retry within a bounded window."""
    deadline = time.time() + 240
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.time() >= deadline:
                raise
        time.sleep(2)

# The harness's per-check budget for this suite: every provisioning wait ends there, so no
# wait is an assertion on elapsed time.
_SUITE_BUDGET_S = 1800.0

CHECK = "delete-cluster-lifecycle"
GROUP = 'cluster-lifecycle'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on an available cluster: it ends gone, unlisted and unusable."""
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-del-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id, timeout_s=_SUITE_BUDGET_S)

    # Independent read: the stored cluster carries what was requested, not just a status word.
    live = _describe_cluster(rs, cluster_id)
    assert live["NodeType"] == NODE_TYPE, f"expected NodeType {NODE_TYPE}, got {live.get('NodeType')!r}"
    assert live["MasterUsername"] == MASTER_USERNAME, (
        f"expected MasterUsername {MASTER_USERNAME}, got {live.get('MasterUsername')!r}"
    )
    assert live["DBName"] == "devdb", f"expected DBName 'devdb', got {live.get('DBName')!r}"
    assert live["Encrypted"] is True, f"expected Encrypted True, got {live.get('Encrypted')!r}"
    ns_prefix = f"arn:aws:redshift:{ctx.region}:{ctx.account}:namespace:"
    # The namespace ARN is not part of this lifecycle contract: when present it must be well-formed.
    ns_arn = live.get("ClusterNamespaceArn") or ""
    if ns_arn:
        assert ns_arn.startswith(ns_prefix) and len(ns_arn) > len(ns_prefix), (
            f"expected ClusterNamespaceArn under {ns_prefix}, got {ns_arn!r}"
        )
    live_tags = {t["Key"]: t["Value"] for t in live.get("Tags", [])}
    assert live_tags.get("sim2real") == CHECK, f"expected tag sim2real={CHECK}, got {live_tags!r}"

    def _tagged():
        return [
            c["ClusterIdentifier"]
            for page in rs.get_paginator("describe_clusters").paginate(TagKeys=["sim2real"], TagValues=[CHECK])
            for c in page["Clusters"]
        ]

    assert cluster_id in _tagged(), "the live cluster is not listed by DescribeClusters filtered to this check's tag"

    deleted = rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)["Cluster"]
    assert deleted["ClusterIdentifier"] == cluster_id, f"unexpected delete response {deleted!r}"

    gone = _wait_for_cluster_gone(rs, cluster_id, timeout_s=_SUITE_BUDGET_S)
    assert gone is None, f"cluster still reachable after delete, status={gone}"

    code, status, message = _refusal(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    assert code == "ClusterNotFound", f"expected ClusterNotFound after deletion, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for DescribeClusters of the deleted cluster, got {status}"
    expected_message = f"Cluster {cluster_id} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Gone beat 2: the listing filtered to this check's tag no longer holds the cluster.
    assert cluster_id not in _tagged(), "the deleted cluster is still listed by DescribeClusters filtered to this check's tag"

    reboot_code, reboot_status, reboot_message = _refusal(lambda: rs.reboot_cluster(ClusterIdentifier=cluster_id))
    assert reboot_code == "ClusterNotFound", (
        f"a mutation against the deleted cluster id must also be refused, got {reboot_code}"
    )
    assert isinstance(reboot_status, int) and 400 <= reboot_status < 500, f"expected HTTP 4xx for RebootCluster of the deleted cluster, got {reboot_status}"
    expected_message = f"Cluster not found: {cluster_id}"
    assert reboot_message == expected_message, f"expected the message {expected_message!r}, got {reboot_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
